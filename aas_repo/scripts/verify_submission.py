#!/usr/bin/env python3
"""Run SDK-independent integrity checks against the final submission artifact."""

from __future__ import annotations

import ast
import hashlib
from pathlib import Path


def literal_assignment(tree: ast.Module, name: str):
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == name for t in node.targets):
            return ast.literal_eval(node.value)
    raise KeyError(name)


def main() -> None:
    path = Path("submission/attack.py")
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)

    classes = {node.name for node in tree.body if isinstance(node, ast.ClassDef)}
    assert "AttackAlgorithm" in classes, "AttackAlgorithm class missing"

    gpt = literal_assignment(tree, "GPT_SEARCH_PROFILES")
    gemma = literal_assignment(tree, "GEMMA_SEARCH_PROFILES")
    max_candidates = literal_assignment(tree, "MAX_CANDIDATES")

    assert len(gpt) == 20 and len(set(gpt)) == 20, "GPT profile pool must contain 20 unique names"
    assert len(gemma) == 20 and len(set(gemma)) == 20, "Gemma search pool must contain 20 unique names"
    assert max_candidates == 2_000, "unexpected candidate cap"
    assert "FORBIDDEN_MARKER" in source, "marker exclusion guard missing"
    assert "_assert_submission_shape" in source, "submission shape guard missing"

    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    print("submission integrity: OK")
    print("gpt profiles:", len(gpt))
    print("gemma profiles:", len(gemma))
    print("sha256:", digest)


if __name__ == "__main__":
    main()
