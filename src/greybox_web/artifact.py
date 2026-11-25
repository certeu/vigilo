"""Bounded offline repository inventory used by artifact-mode assessments."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath

MAX_FILE_BYTES = 200_000
MAX_FILES = 2_000
TEXT_EXTS = {".c", ".conf", ".cs", ".go", ".html", ".ini", ".java", ".js", ".json", ".jsx", ".kt", ".lock", ".md", ".php", ".properties", ".py", ".rb", ".rs", ".sh", ".toml", ".ts", ".tsx", ".txt", ".xml", ".yaml", ".yml"}
MANIFEST_NAMES = {"package.json", "package-lock.json", "pyproject.toml", "poetry.lock", "uv.lock", "requirements.txt", "go.mod", "go.sum", "cargo.toml", "cargo.lock", "gemfile", "gemfile.lock", "pom.xml", "composer.json", "composer.lock"}


def target_root(uploads_dir: str, target_id) -> Path:
    return Path(uploads_dir) / "greybox-artifacts" / str(target_id)


def _safe(root: Path, name: str) -> Path:
    rel = PurePosixPath(name)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("unsafe artifact path")
    path = root.joinpath(*rel.parts).resolve()
    if root.resolve() not in path.parents:
        raise ValueError("unsafe artifact path")
    return path


class Reader:
    def __init__(self, root: Path) -> None:
        self.root = root

    async def __call__(self, name: str | None = None):
        if name:
            path = _safe(self.root, name)
            if not path.is_file():
                return {"path": name, "error": "not found"}
            data = path.read_bytes()[:MAX_FILE_BYTES]
            binary = b"\x00" in data
            return {"path": name, "size": path.stat().st_size,
                    "truncated": path.stat().st_size > len(data),
                    "binary": binary,
                    "content": "" if binary else data.decode("utf-8", "replace")}
        rows = []
        if not self.root.is_dir():
            return rows
        for path in sorted(self.root.rglob("*")):
            if not path.is_file() or len(rows) >= MAX_FILES:
                continue
            rel = path.relative_to(self.root).as_posix()
            size = path.stat().st_size
            digest = hashlib.sha256(path.read_bytes()[:MAX_FILE_BYTES]).hexdigest()
            rows.append({"path": rel, "size": size, "sha256_prefix": digest[:16],
                         "manifest": path.name.lower() in MANIFEST_NAMES,
                         "text": path.suffix.lower() in TEXT_EXTS or path.name.lower() in MANIFEST_NAMES})
        return rows
