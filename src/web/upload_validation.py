"""Shared filename extension rules for analysis upload endpoints."""

from pathlib import Path
from typing import Iterable

from src.analyzers.file_type_router import FileTypeRouter


EMAIL_ALLOWED_EXTENSIONS = {".eml"}
FILE_ALLOWED_EXTENSIONS = set(FileTypeRouter.EXTENSION_MAP.keys())


def has_allowed_extension(
    filename: str | None,
    allowed_extensions: Iterable[str],
    *,
    allow_no_suffix: bool = False,
) -> bool:
    """Return whether a filename's last suffix is allowed.

    Trailing whitespace and dots are ignored to match common filename
    normalization behavior. Only ``Path.suffix`` is considered, so a name
    such as ``sample.exe.txt`` is judged by ``.txt``.
    """
    normalized_name = (filename or "").rstrip(" .")
    suffix = Path(normalized_name).suffix.lower()
    if not suffix:
        return allow_no_suffix
    return suffix in {extension.lower() for extension in allowed_extensions}
