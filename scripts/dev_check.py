"""Developer checks: compile, unit tests, registry and data summary.

    python scripts/dev_check.py
"""

from __future__ import annotations

import compileall
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    sys.path.insert(0, str(ROOT))
    print(f"project : {ROOT}")

    print("\n[1/3] compile")
    ok = compileall.compile_dir(str(ROOT / "nulltrace"), quiet=1, force=False)
    ok = compileall.compile_file(str(ROOT / "scan.py"), quiet=1) and ok
    print("      " + ("ok" if ok else "FAILED"))

    print("\n[2/3] unit tests")
    result = subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                            cwd=ROOT)
    tests_ok = result.returncode == 0

    print("\n[3/3] inventory")
    from nulltrace.datasets import reloadable
    from nulltrace.modules import all_modules, grouped

    modules = all_modules()
    for category, items in grouped().items():
        print(f"      {category:<14} {len(items)} modules")
    print(f"      total          {len(modules)} modules")
    print(f"      data files     {len(reloadable())} ({', '.join(reloadable())})")
    keys = sum(1 for m in modules if m.keys)
    print(f"      key-gated      {keys} modules")

    print("\nresult:", "ok" if ok and tests_ok else "problems found")
    return 0 if ok and tests_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
