#!/usr/bin/env python3
"""Run the versioned synthetic known-answer qualification suite.

Synthetic mode is deterministic and never contacts external systems.  Live
mode is intentionally explicit and requires secret-file configuration before
any adapter is constructed; it is a deployment rehearsal entry point, not a
silent fallback to synthetic data.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))

from known_answer.harness import KnownAnswerError, run_suite  # noqa: E402


class LiveConfigurationError(RuntimeError):
    """Raised when live qualification lacks required deployment settings."""


def _require_live_configuration() -> dict[str, str]:
    required = {
        "THREAT_HUNTING_SPLUNK_URL": "Splunk endpoint",
        "THREAT_HUNTING_SPLUNK_TOKEN_FILE": "Splunk token secret-file path",
        "THREAT_HUNTING_MODEL_PROVIDER": "model provider",
        "THREAT_HUNTING_MODEL_NAME": "model name",
    }
    missing = [label for name, label in required.items() if not os.environ.get(name)]
    if missing:
        raise LiveConfigurationError(
            "live qualification requires configured secret-file/runtime values: "
            + ", ".join(missing)
        )
    token_path = Path(os.environ["THREAT_HUNTING_SPLUNK_TOKEN_FILE"])
    try:
        token = token_path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as exc:
        raise LiveConfigurationError("could not read the configured Splunk token secret file") from exc
    if not token:
        raise LiveConfigurationError("the configured Splunk token secret file is empty")
    # Never return or print the token.  The returned metadata is safe to log.
    return {
        "splunk_url": os.environ["THREAT_HUNTING_SPLUNK_URL"],
        "model_provider": os.environ["THREAT_HUNTING_MODEL_PROVIDER"],
        "model_name": os.environ["THREAT_HUNTING_MODEL_NAME"],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("synthetic", "live"), default="synthetic")
    parser.add_argument("--json", action="store_true", help="emit machine-readable results")
    args = parser.parse_args(argv)
    try:
        if args.mode == "live":
            configuration = _require_live_configuration()
            raise LiveConfigurationError(
                "live adapter rehearsal requires a non-production Splunk fixture deployment; "
                f"configuration validated for {configuration['model_provider']}:{configuration['model_name']}"
            )
        result = run_suite()
    except (KnownAnswerError, LiveConfigurationError) as exc:
        print(f"known-answer qualification failed: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(result, sort_keys=True))
    else:
        print(
            f"known-answer suite: {'PASS' if result['passed'] else 'FAIL'}; "
            f"{result['scenario_count']} scenarios; "
            f"evidence recovery {result['recovery_percent']:.2f}%; "
            f"queries {result['query_count']}; model calls {result['model_calls']}"
        )
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
