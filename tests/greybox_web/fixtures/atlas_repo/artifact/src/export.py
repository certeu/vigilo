from pathlib import Path


def export_path(base: Path, tenant: str, name: str) -> Path:
    return base / tenant / name
