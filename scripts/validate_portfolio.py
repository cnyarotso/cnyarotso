#!/usr/bin/env python3
"""Validate local Markdown links and common portfolio hygiene issues."""

from __future__ import annotations

import re
import sys
from pathlib import Path

LINK_PATTERN = re.compile(r"!?\[[^\]]*\]\(([^)]+)\)")
PLACEHOLDERS = ("your-email@example.com", "TODO", "ðŸ", "Ã", "�")


def validate(root: Path) -> list[str]:
    errors: list[str] = []
    for markdown in sorted(root.rglob("*.md")):
        content = markdown.read_text(encoding="utf-8")
        if content.count("```") % 2:
            errors.append(f"{markdown}: unbalanced fenced code block")
        for placeholder in PLACEHOLDERS:
            if placeholder in content:
                errors.append(f"{markdown}: contains placeholder or encoding artifact {placeholder!r}")
        for match in LINK_PATTERN.finditer(content):
            target = match.group(1).strip().split("#", 1)[0]
            if not target or target.startswith(("http://", "https://", "mailto:")):
                continue
            resolved = (markdown.parent / target).resolve()
            if resolved.is_dir():
                resolved = resolved / "README.md"
            if not resolved.exists():
                errors.append(f"{markdown}: broken relative link {target!r}")
    return errors


def main() -> int:
    root = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
    errors = validate(root)
    if errors:
        print("Portfolio validation failed:")
        for error in errors:
            print(f"- {error}")
        return 1
    print("Portfolio validation passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
