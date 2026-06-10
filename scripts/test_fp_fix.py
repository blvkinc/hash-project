import os
from sqlalchemy.orm import Session
from core.database import SessionLocal, init_db
from core.models import FileLog
from core.background_analysis import process_pending_analysis

# Initialize DB for testing
init_db()

def create_mock_log(path: str, content: str, event_type: str = "new") -> FileLog:
    # Ensure there's a log simulating a "new" file with the given content
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
    # Test 1: Fake binary file
    print("=== Testing Binary File Fake ===")
    binary_content = "Binary/Unreadable"
    bin_path = os.path.abspath("test_binary.png")
    
    # We simulate what scanner/watcher would give us: "Binary/Unreadable"
    session = SessionLocal()
    # Clean previous test
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

    # Test 2: Heuristic Fake Positive triggered in Temp dir (Low priority Tier 4)
    print("\n=== Testing Tier 4 Escalation Override ===")
    fp_content = "This temp file has c2 and callback in it"
    fp_path = os.path.abspath(r"C:\Windows\Temp\test_heuristic.txt") # Windows Tier 4 path
    if not os.path.exists(r"C:\Windows\Temp"):
        # Fallback to linux tier 4 for cross-platform testing
        fp_path = os.path.abspath(r"/tmp/test_heuristic.txt")
        
    create_mock_log(fp_path, fp_content)
    
    print("Running process_pending_analysis...")
    processed = process_pending_analysis()
    print(f"Processed logs: {processed}")

    session = SessionLocal()
    fp_log = session.query(FileLog).filter_by(path=fp_path).first()
    print("FP file risk score:", fp_log.risk_score)
    print("FP logic override:", fp_log.analysis_json.get('tier_override'))
    print("FP file priority:", fp_log.priority)
    session.close()

    print("\nDone.")
