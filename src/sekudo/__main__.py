"""Entry point: `sekudo` (MCP server over stdio) and `sekudo --selftest`."""

from __future__ import annotations

import sys


def main() -> None:
    if "--selftest" in sys.argv:
        from .checks import catalog
        cats = catalog()
        print(f"sekudo selftest: {len(cats)} checks registered")
        for c in cats:
            print(f"  {c.id:24} {c.owasp:40} {c.name}")
        return
    from .server import run
    run()


if __name__ == "__main__":
    main()
