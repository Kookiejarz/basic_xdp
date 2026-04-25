"""Port whitelist auto-sync daemon — compat entry point.

All logic lives in the auto_xdp package. This file is kept as an
entry-point shim so existing installations and scripts work unchanged.
"""
from auto_xdp.cli import main

if __name__ == "__main__":
    main()
