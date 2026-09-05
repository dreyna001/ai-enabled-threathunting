"""Container health command for the background worker."""

from __future__ import annotations

from threat_hunting.health import check_readiness


def run() -> None:
    """Exit successfully only when worker dependencies are ready."""

    result = check_readiness()
    raise SystemExit(0 if result.status == "ready" else 1)


if __name__ == "__main__":
    run()

