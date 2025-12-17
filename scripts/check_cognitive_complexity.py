#!/usr/bin/env python3
"""Check cognitive complexity of Python functions.

Usage:
    uv run python scripts/check_cognitive_complexity.py src/mcp_docker/tools/image.py
    uv run python scripts/check_cognitive_complexity.py src/mcp_docker/ --threshold 15
"""

import ast
import sys
from pathlib import Path

from cognitive_complexity.api import get_cognitive_complexity

DEFAULT_THRESHOLD = 15
MIN_ARGS = 2


def check_file(filepath: Path, threshold: int) -> list[tuple[str, int, int]]:
    """Check cognitive complexity of all functions in a file.

    Returns list of (function_name, line_number, complexity) for violations.
    """
    violations = []
    try:
        tree = ast.parse(filepath.read_text())
    except SyntaxError as e:
        print(f"  Syntax error in {filepath}: {e}")
        return violations

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            complexity = get_cognitive_complexity(node)
            if complexity > threshold:
                violations.append((node.name, node.lineno, complexity))

    return violations


def main() -> int:
    """Main entry point."""
    if len(sys.argv) < MIN_ARGS:
        print(__doc__)
        return 1

    path = Path(sys.argv[1])
    threshold = DEFAULT_THRESHOLD

    # Parse --threshold argument
    if "--threshold" in sys.argv:
        idx = sys.argv.index("--threshold")
        if idx + 1 < len(sys.argv):
            threshold = int(sys.argv[idx + 1])

    files = list(path.rglob("*.py")) if path.is_dir() else [path]
    total_violations = 0

    for filepath in sorted(files):
        violations = check_file(filepath, threshold)
        for func_name, line_no, complexity in violations:
            msg = f"{func_name} has cognitive complexity {complexity} > {threshold}"
            print(f"{filepath}:{line_no}: {msg}")
            total_violations += 1

    if total_violations:
        print(f"\nFound {total_violations} function(s) exceeding threshold of {threshold}")
        return 1

    print(f"All functions have cognitive complexity <= {threshold}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
