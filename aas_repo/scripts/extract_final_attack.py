#!/usr/bin/env python3
"""Extract the embedded ``attack_code`` string from the final notebook source."""

from __future__ import annotations

import argparse
import ast
from pathlib import Path


def extract_attack_code(path: Path) -> str:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in tree.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == "attack_code" for target in node.targets):
            continue
        value = ast.literal_eval(node.value)
        if isinstance(value, str):
            return value
    raise ValueError(f"attack_code string not found in {path}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, nargs="?", default=Path("notebooks/final_submission.py"))
    parser.add_argument("--output", type=Path, default=Path("submission/attack.py"))
    args = parser.parse_args()

    code = extract_attack_code(args.source)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(code, encoding="utf-8")
    print(f"wrote {args.output} ({len(code.splitlines())} lines, {len(code.encode())} bytes)")


if __name__ == "__main__":
    main()
