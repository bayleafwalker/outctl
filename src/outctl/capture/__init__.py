"""Linux direct-argv capture with bounded, recoverable raw spools."""

from outctl.capture.recovery import RecoveryRecord, recover_partials
from outctl.capture.runner import CaptureResult, CommandResult, capture_command

__all__ = [
    "CaptureResult",
    "CommandResult",
    "RecoveryRecord",
    "capture_command",
    "recover_partials",
]
