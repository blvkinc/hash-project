"""Small, bounded file-content reads used by the analysis pipeline."""


UNREADABLE_CONTENT = "Binary/Unreadable"


def read_text_snippet(file_path: str, max_chars: int = 5000) -> str:
    """Return a UTF-8 text prefix, or a stable marker for binary/unreadable files."""
    try:
        with open(file_path, "rb") as file_handle:
            if b"\x00" in file_handle.read(min(1024, max_chars)):
                return UNREADABLE_CONTENT

        with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as file_handle:
            return file_handle.read(max_chars)
    except (OSError, UnicodeError):
        return UNREADABLE_CONTENT
