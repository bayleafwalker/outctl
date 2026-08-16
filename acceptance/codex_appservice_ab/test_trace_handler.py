from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from trace_handler import TRACE_SCHEMA_VERSION, capture_runtime_trace


class TraceHandlerTests(unittest.TestCase):
    def test_structural_ptc_evidence_and_caller_graph(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "events.jsonl"
            trace = root / "runtime-trace.jsonl"
            summary_path = root / "runtime-trace-summary.json"
            lines = [
                {
                    "type": "custom_tool_call",
                    "name": "exec",
                    "code_mode_only": True,
                    "programmatic_tool_calling": {"allowed_callers": ["program"]},
                },
                {
                    "type": "program",
                    "call_id": "call_prog_123",
                    "code": "await Promise.all([tools.exec_command({cmd: 'pwd'})])",
                },
                {
                    "type": "function_call",
                    "call_id": "call_fn_456",
                    "caller": {"type": "program", "caller_id": "call_prog_123"},
                    "name": "exec_command",
                },
                {
                    "type": "function_call_output",
                    "call_id": "call_fn_456",
                    "caller": {"type": "program", "caller_id": "call_prog_123"},
                    "status": "completed",
                },
                {
                    "type": "program_output",
                    "call_id": "call_prog_123",
                    "output": {"ok": True},
                },
            ]
            source.write_text("\n".join(json.dumps(value) for value in lines) + "\n")
            source_bytes = source.read_bytes()
            summary = capture_runtime_trace(source, trace, summary_path)

            self.assertEqual(summary["schema_version"], TRACE_SCHEMA_VERSION)
            self.assertEqual(summary["handler_status"], "complete")
            self.assertTrue(summary["source"]["raw_preserved"])
            self.assertEqual(summary["source"]["sha256"], hashlib.sha256(source_bytes).hexdigest())
            self.assertEqual(summary["parsed_events"], 5)
            for marker in (
                "custom_tool_call",
                "code_mode_only",
                "ptc",
                "ptc_config",
                "ptc_caller_linkage",
                "program_item",
                "program_output",
                "function_call",
                "function_call_output",
                "exec_envelope",
                "exec_tool",
                "promise_all",
            ):
                self.assertTrue(summary["marker_presence"][marker], marker)
            graph = summary["ptc_caller_graph"]
            self.assertTrue(graph["caller_linkage_valid"])
            self.assertEqual(len(graph["linked_programs"]), 1)
            self.assertEqual(summary["marker_counts"]["program_item"], 1)
            self.assertEqual(summary["marker_counts"]["function_call"], 1)
            self.assertEqual(summary["marker_counts"]["function_call_output"], 1)
            self.assertEqual(graph["orphan_nested_calls"], [])
            self.assertEqual(graph["orphan_program_outputs"], [])
            self.assertEqual(graph["orphan_function_call_outputs"], [])
            self.assertEqual(
                summary["evidence_domains"]["program_behavior"]["marker_counts"]["exec_tool"],
                1,
            )
            behavior = summary["evidence_domains_extra"]["program_behavior"]
            self.assertEqual(behavior["programs_using_tools"]["exec_command"], 1)
            self.assertEqual(behavior["tool_invocations"]["exec_command"], 1)
            self.assertEqual(behavior["programs_using_promise_all"], 1)
            normalized = trace.read_text()
            self.assertIn("tools.exec_command", normalized)
            self.assertIn("Promise.all", normalized)
            self.assertNotIn('"code":', normalized)
            self.assertNotIn("redacted_event", normalized)

    def test_app_server_raw_item_envelope_is_structural_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "events.jsonl"
            trace = root / "trace.jsonl"
            summary_path = root / "summary.json"
            program_id = "call_raw_program"
            child_id = "call_raw_child"
            caller = {"type": "program", "caller_id": program_id}
            lines = [
                {
                    "method": "codex/event/raw_response_item_completed",
                    "params": {
                        "threadId": "thread_1",
                        "turnId": "turn_1",
                        "item": {
                            "type": "program",
                            "call_id": program_id,
                            "code": "await Promise.all([tools.exec_command({cmd: 'true'})])",
                        },
                    },
                },
                {
                    "method": "rawResponseItem/completed",
                    "params": {
                        "item": {
                            "type": "custom_tool_call",
                            "name": "exec",
                            "input": "await Promise.all([tools.exec_command({cmd: 'true'})])",
                        }
                    },
                },
                {
                    "method": "rawResponseItem/completed",
                    "params": {
                        "item": {
                            "type": "custom_tool_call_output",
                            "call_id": "call_exec",
                            "output": [],
                        }
                    },
                },
                {
                    "method": "codex/event/raw_response_item_completed",
                    "params": {
                        "item": {
                            "type": "function_call",
                            "call_id": child_id,
                            "caller": caller,
                        }
                    },
                },
                {
                    "method": "codex/event/raw_response_item_completed",
                    "params": {
                        "item": {
                            "type": "function_call_output",
                            "call_id": child_id,
                            "caller": caller,
                        }
                    },
                },
                {
                    "method": "codex/event/raw_response_item_completed",
                    "params": {
                        "item": {"type": "program_output", "call_id": program_id}
                    },
                },
            ]
            source.write_text("\n".join(json.dumps(value) for value in lines) + "\n")
            summary = capture_runtime_trace(source, trace, summary_path)
            self.assertEqual(summary["event_type_counts"]["program"], 1)
            self.assertEqual(summary["marker_counts"]["program_item"], 1)
            self.assertEqual(summary["marker_counts"]["function_call"], 1)
            self.assertEqual(summary["marker_counts"]["function_call_output"], 1)
            behavior = summary["evidence_domains_extra"]["program_behavior"]
            self.assertEqual(behavior["programs_using_tools"]["exec_command"], 2)
            self.assertEqual(behavior["tool_invocations"]["exec_command"], 2)
            self.assertEqual(behavior["programs_using_promise_all"], 2)
            self.assertTrue(summary["marker_presence"]["program_item"])
            self.assertTrue(summary["marker_presence"]["function_call"])
            self.assertTrue(summary["marker_presence"]["program_output"])
            self.assertTrue(summary["marker_presence"]["ptc_caller_linkage"])
            self.assertTrue(summary["ptc_caller_graph"]["caller_linkage_valid"])
            self.assertTrue(summary["marker_presence"]["custom_tool_call"])
            self.assertTrue(summary["marker_presence"]["custom_tool_call_output"])
            self.assertTrue(summary["marker_presence"]["exec_envelope"])
            self.assertTrue(summary["marker_presence"]["exec_tool"])
            self.assertTrue(summary["marker_presence"]["promise_all"])

    def test_prose_does_not_create_protocol_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "events.jsonl"
            trace = root / "trace.jsonl"
            summary_path = root / "summary.json"
            source.write_text(
                json.dumps(
                    {
                        "type": "agent_message",
                        "message": (
                            "This prose mentions custom_tool_call, code_mode_only, "
                            "function_call, programmatic_tool_calling, Promise.all, "
                            "and tools.exec_command."
                        ),
                    }
                )
                + "\n"
            )
            summary = capture_runtime_trace(source, trace, summary_path)
            self.assertEqual(summary["marker_counts"], {})
            self.assertFalse(any(summary["marker_presence"].values()))
            normalized = trace.read_text()
            self.assertNotIn("This prose mentions", normalized)
            self.assertNotIn("Promise.all", normalized)

    def test_normalized_trace_is_metadata_first_and_does_not_copy_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "events.jsonl"
            trace = root / "trace.jsonl"
            summary_path = root / "summary.json"
            source.write_text(
                json.dumps(
                    {
                        "type": "program",
                        "call_id": "call-secret-test",
                        "code": (
                            "const token = 'opaque-super-secret-value-12345'; "
                            "return await tools.exec_command({cmd: 'true'});"
                        ),
                        "token": "opaque-super-secret-value-12345",
                        "password": "hunter2-long",
                        "api_key": "opaque-api-value-abcdef",
                    }
                )
                + "\n"
            )
            summary = capture_runtime_trace(
                source,
                trace,
                summary_path,
                exact_redactions=("opaque-super-secret-value-12345",),
            )
            normalized = trace.read_text()
            for secret in (
                "opaque-super-secret-value-12345",
                "hunter2-long",
                "opaque-api-value-abcdef",
            ):
                self.assertNotIn(secret, normalized)
            self.assertNotIn('"redacted_event"', normalized)
            self.assertFalse(summary["normalized_payload_policy"]["raw_event_bodies_included"])
            self.assertFalse(summary["normalized_payload_policy"]["program_code_included"])

    def test_bounded_trace_keeps_source_complete_and_reports_truncation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "events.jsonl"
            trace = root / "trace.jsonl"
            summary_path = root / "summary.json"
            source.write_text(
                "\n".join(
                    json.dumps({"type": "item.completed", "value": "x" * 200})
                    for _ in range(5)
                )
                + "\n"
            )
            original = source.read_bytes()
            summary = capture_runtime_trace(
                source,
                trace,
                summary_path,
                max_events=1,
                max_trace_bytes=16 * 1024,
            )
            self.assertEqual(source.read_bytes(), original)
            self.assertTrue(summary["normalized_trace"]["truncated"])
            self.assertEqual(summary["parsed_events"], 5)
            self.assertEqual(summary["normalized_trace"]["events_written"], 1)

    def test_malformed_lines_are_counted_without_losing_valid_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "events.jsonl"
            source.write_text('{"type":"thread.started"}\nnot-json\n')
            summary = capture_runtime_trace(
                source,
                root / "trace.jsonl",
                root / "summary.json",
            )
            self.assertEqual(summary["parsed_events"], 1)
            self.assertEqual(summary["invalid_line_count"], 1)
            self.assertEqual(summary["handler_status"], "complete")


if __name__ == "__main__":
    unittest.main()
