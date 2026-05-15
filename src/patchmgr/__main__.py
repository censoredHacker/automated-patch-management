"""Allow running the tool as `python -m patchmgr ...`.

This is a thin wrapper that simply delegates to the click-based CLI
defined in `patchmgr.cli.main`.
"""

from patchmgr.cli import main

if __name__ == "__main__":  # pragma: no cover - trivial dispatcher
    main()
