"""Small, bounded file-content reads used by the analysis pipeline."""
from __future__ import annotations

import os
import re


UNREADABLE_CONTENT = "Binary/Unreadable"

ANALYZABLE_BINARY_EXTENSIONS = {
    ".dll", ".dylib", ".exe", ".ko", ".ocx", ".scr", ".so", ".sys",
}

_ASCII_STRING = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16LE_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_BINARY_SIGNAL_TERMS = (
    "cmd.exe", "powershell", "/bin/sh", "/bin/bash", "/shell",
    "createprocess", "shellexecute", "winexec", "winhttp", "winsock",
    "socket", "connect", "sendmessage", "getupdates", "telegram",
    "http://", "https://", "currentversion\\run", "scheduledtask",
    "mimikatz", "lsass", "meterpreter", "ransom", "encrypt",
)


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


def read_analysis_snippet(
    file_path: str,
    max_chars: int = 65_536,
    max_binary_bytes: int = 4_000_000,
) -> str:
    """
    Return bounded text evidence for analysis.

    Executables are never loaded or run. Supported binaries are represented by
    ranked printable strings for the normal heuristic and model stages.
    """
    text = read_text_snippet(file_path, max_chars=max_chars)
    if text != UNREADABLE_CONTENT:
        return text

    ext = os.path.splitext(file_path.lower())[1]
    if ext not in ANALYZABLE_BINARY_EXTENSIONS:
        return UNREADABLE_CONTENT

    try:
        with open(file_path, "rb") as file_handle:
            data = file_handle.read(max(0, max_binary_bytes))
        file_size = os.path.getsize(file_path)
    except OSError:
        return UNREADABLE_CONTENT

    strings = _extract_ranked_binary_strings(data)
    if not strings:
        return UNREADABLE_CONTENT

    header = (
        "[Static binary evidence; file was not executed]\n"
        f"format={_binary_format(data)}; size={file_size}; "
        f"bytes_inspected={len(data)}; truncated={str(file_size > len(data)).lower()}\n"
        "printable_strings:\n"
    )
    room = max(0, max_chars - len(header))
    return header + "\n".join(strings)[:room]


def _extract_ranked_binary_strings(data: bytes) -> list[str]:
    """Extract unique ASCII and UTF-16LE strings, with threat signals first."""
    found = [
        match.group(0).decode("ascii", errors="ignore")
        for match in _ASCII_STRING.finditer(data)
    ]
    found.extend(
        match.group(0).decode("utf-16le", errors="ignore")
        for match in _UTF16LE_STRING.finditer(data)
    )

    unique: list[str] = []
    seen: set[str] = set()
    for value in found:
        cleaned = value.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        unique.append(cleaned)

    def signal_rank(item: tuple[int, str]) -> tuple[int, int]:
        index, value = item
        lower = value.lower()
        is_signal = any(term in lower for term in _BINARY_SIGNAL_TERMS)
        return (0 if is_signal else 1, index)

    return [value for _, value in sorted(enumerate(unique), key=signal_rank)]


def _binary_format(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "PE"
    if data.startswith(b"\x7fELF"):
        return "ELF"
    if data[:4] in {
        b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    }:
        return "Mach-O"
    return "unknown"
