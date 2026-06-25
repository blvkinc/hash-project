"""Local smoke checks for binary handling and Tier 4 content overrides."""

import os
from sqlalchemy.orm import Session
from core.database import SessionLocal, init_db
from core.models import FileLog
from core.background_analysis import process_pending_analysis

init_db()

def create_mock_log(path: str, content: str, event_type: str = "new") -> FileLog:
    session = SessionLocal()
    log = FileLog(
        path=path,
        event_type=event_type,
        status='pending',
        analysis_json={'diff': content, 'metadata': {'size': len(content)}},
        details="Mock file trigger"
    )
    session.add(log)
    session.commit()
    session.refresh(log)
    session.close()
    return log

if __name__ == "__main__":
    print("=== Binary/unreadable file handling ===")
    binary_content = "Binary/Unreadable"
    bin_path = os.path.abspath("test_binary.png")

    session = SessionLocal()
    session.query(FileLog).filter(FileLog.path.like("%test_%")).delete()
    session.commit()
    session.close()

    create_mock_log(bin_path, binary_content)

    print("Running process_pending_analysis...")
    processed = process_pending_analysis()
    print(f"Processed logs: {processed}")

    session = SessionLocal()
    bin_log = session.query(FileLog).filter_by(path=bin_path).first()
    print("Binary file risk score:", bin_log.risk_score)
    print("Binary file priority:", bin_log.priority)
    session.close()

    print("\n=== Tier 4 escalation override ===")
    fp_content = "This temp file has c2 and callback in it"
    fp_path = os.path.abspath(r"C:\Windows\Temp\test_heuristic.txt")
    if not os.path.exists(r"C:\Windows\Temp"):
        fp_path = os.path.abspath(r"/tmp/test_heuristic.txt")

    create_mock_log(fp_path, fp_content)

    print("Running process_pending_analysis...")
    processed = process_pending_analysis()
    print(f"Processed logs: {processed}")

    session = SessionLocal()
    fp_log = session.query(FileLog).filter_by(path=fp_path).first()
    print("Tier 4 file risk score:", fp_log.risk_score)
    print("Tier 4 override:", fp_log.analysis_json.get('tier_override'))
    print("Tier 4 file priority:", fp_log.priority)
    session.close()

    print("\nDone.")
