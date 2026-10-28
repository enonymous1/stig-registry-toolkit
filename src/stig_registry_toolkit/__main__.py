"""Run the GUI when invoked with no arguments, else the CLI."""

from __future__ import annotations

import sys


def main() -> int:
    if len(sys.argv) <= 1:
        try:
            from .gui import run_gui  # noqa: PLC0415
        except ImportError:
            print(
                "The GUI needs PyQt6: "
                "pip install 'stig-registry-toolkit[gui]' on Windows. "
                "Use 'stig-registry-toolkit check --help' instead.",
                file=sys.stderr,
            )
            return 2
        return run_gui()
    from .cli import main as cli_main  # noqa: PLC0415

    return cli_main(sys.argv[1:])


if __name__ == "__main__":
    raise SystemExit(main())
