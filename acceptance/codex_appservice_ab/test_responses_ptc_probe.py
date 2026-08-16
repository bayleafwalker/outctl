from __future__ import annotations

import json
import tempfile
import unittest
from copy import deepcopy
from pathlib import Path
from typing import Any

from responses_ptc_probe import run_probe


class FakeTransport:
    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = responses
        self.payloads: list[dict[str, Any]] = []

    def create(self, payload: dict[str, Any]) -> tuple[dict[str, Any], bytes, float]:
        self.payloads.append(deepcopy(payload))
        response = self.responses[len(self.payloads) - 1]
        return response, json.dumps(response, separators=(",", ":")).encode(), 12.5


class ResponsesPtcProbeTests(unittest.TestCase):
    def test_minimal_ptc_loop_captures_trace_graph_and_metrics(self) -> None:
        program_call_id = "call_prog_123"
        inventory_call_id = "call_inventory_123"
        demand_call_id = "call_demand_123"
        caller = {"type": "program", "caller_id": program_call_id}
        first = {
            "id": "resp_1",
            "status": "completed",
            "output": [
                {
                    "type": "program",
                    "id": "prog_123",
                    "call_id": program_call_id,
                    "code": (
                        "const x = await Promise.all([tools.get_inventory(), "
                        "tools.get_demand()]);"
                    ),
                    "fingerprint": "opaque",
                },
                {
                    "type": "function_call",
                    "id": "fc_inventory",
                    "call_id": inventory_call_id,
                    "name": "get_inventory",
                    "arguments": '{"sku":"sku_123"}',
                    "caller": caller,
                },
                {
                    "type": "function_call",
                    "id": "fc_demand",
                    "call_id": demand_call_id,
                    "name": "get_demand",
                    "arguments": '{"sku":"sku_123"}',
                    "caller": caller,
                },
            ],
            "usage": {"input_tokens": 100, "output_tokens": 20, "total_tokens": 120},
        }
        second = {
            "id": "resp_2",
            "status": "completed",
            "output": [
                {
                    "type": "program_output",
                    "id": "prog_out_123",
                    "call_id": program_call_id,
                    "result": '{"shortage_units":0}',
                    "status": "completed",
                },
                {"type": "message", "role": "assistant", "content": []},
            ],
            "output_text": '{"shortage_units":0}',
            "usage": {"input_tokens": 80, "output_tokens": 10, "total_tokens": 90},
        }
        transport = FakeTransport([first, second])

        with tempfile.TemporaryDirectory() as temporary:
            metrics = run_probe(
                output_root=Path(temporary),
                transport=transport,
            )
            trace_summary = json.loads(
                (Path(temporary) / "runtime-trace-summary.json").read_text()
            )

            self.assertEqual(metrics["responses"], 2)
            self.assertEqual(metrics["continuations"], 1)
            self.assertEqual(metrics["tool_calls"], 2)
            self.assertEqual(metrics["function_call_outputs_sent"], 2)
            self.assertEqual(metrics["usage_total"]["input_tokens"], 180)
            self.assertEqual(metrics["item_counts"]["program"], 1)
            self.assertEqual(metrics["item_counts"]["program_output"], 1)
            self.assertTrue(metrics["request"]["programmatic_tool_calling_enabled"])
            self.assertEqual(
                metrics["request"]["allowed_callers"],
                {"get_demand": ["programmatic"], "get_inventory": ["programmatic"]},
            )
            self.assertTrue(trace_summary["marker_presence"]["program_item"])
            self.assertTrue(trace_summary["marker_presence"]["program_output"])
            self.assertTrue(trace_summary["marker_presence"]["function_call"])
            self.assertTrue(trace_summary["marker_presence"]["function_call_output"])
            self.assertTrue(trace_summary["marker_presence"]["ptc_caller_linkage"])
            self.assertTrue(trace_summary["ptc_caller_graph"]["caller_linkage_valid"])
            self.assertEqual(len(trace_summary["ptc_caller_graph"]["linked_programs"]), 1)
            normalized = (Path(temporary) / "runtime-trace.jsonl").read_text()
            self.assertNotIn('"code":', normalized)
            self.assertNotIn('"result":', normalized)
            self.assertTrue((Path(temporary) / "raw-responses" / "0001.json").is_file())
            self.assertTrue(transport.payloads[1]["store"] is False)
            self.assertEqual(len(transport.payloads[1]["input"]), 6)


if __name__ == "__main__":
    unittest.main()
