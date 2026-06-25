"""Unit tests for the IntegrityGuard core modules."""
import os
import sys
import unittest
import tempfile
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine

# Add project root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.hasher import calculate_file_hash, get_file_metadata
from core.models import Base, AnalysisCache, FileIdentity, FileRecord, FileLog, ScanSession


class TestHasher(unittest.TestCase):
    """Tests for the hashing module."""

    def setUp(self):
        self.test_file = tempfile.NamedTemporaryFile(delete=False, mode='w+', suffix='.txt')
        self.test_file.write("Hello, World!")
        self.test_file.close()

    def tearDown(self):
        os.unlink(self.test_file.name)

    def test_default_xxh3_hash(self):
        expected = "531df2844447dd5077db03842cd75395"
        result = calculate_file_hash(self.test_file.name)
        self.assertEqual(result, expected)

    def test_blake3_hash(self):
        expected = "288a86a79f20a3d6dccdca7713beaed178798296bdfa7913fa2a62d9727bf8f8"
        result = calculate_file_hash(self.test_file.name, algorithm='blake3')
        self.assertEqual(result, expected)

    def test_sha256_hash(self):
        expected = "dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f"
        result = calculate_file_hash(self.test_file.name, algorithm='sha256')
        self.assertEqual(result, expected)

    def test_hash_consistency(self):
        h1 = calculate_file_hash(self.test_file.name)
        h2 = calculate_file_hash(self.test_file.name)
        self.assertEqual(h1, h2)

    def test_metadata_extraction(self):
        meta = get_file_metadata(self.test_file.name)
        self.assertIsNotNone(meta)
        self.assertEqual(meta['size'], 13)
        self.assertIn('mtime', meta)
        self.assertIn('path', meta)

    def test_metadata_nonexistent_file(self):
        meta = get_file_metadata('/nonexistent/file.txt')
        self.assertIsNone(meta)


class TestModels(unittest.TestCase):
    """Tests for the database models."""

    def setUp(self):
        self.engine = create_engine('sqlite:///:memory:')
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine)

    def test_file_record_create(self):
        session = self.Session()
        record = FileRecord(path='/test/file.txt', hash='abc123', is_baseline=True)
        session.add(record)
        session.commit()

        result = session.query(FileRecord).first()
        self.assertEqual(result.path, '/test/file.txt')
        self.assertEqual(result.hash, 'abc123')
        self.assertTrue(result.is_baseline)
        session.close()

    def test_file_log_with_priority(self):
        session = self.Session()
        log = FileLog(
            path='/test/file.txt',
            event_type='modified',
            old_hash='oldhash123',
            new_hash='newhash456',
            priority='high',
            details='Hash changed',
        )
        session.add(log)
        session.commit()

        result = session.query(FileLog).first()
        self.assertEqual(result.event_type, 'modified')
        self.assertEqual(result.old_hash, 'oldhash123')
        self.assertEqual(result.new_hash, 'newhash456')
        self.assertEqual(result.priority, 'high')
        self.assertEqual(result.status, 'pending')
        session.close()

    def test_file_log_default_priority(self):
        session = self.Session()
        log = FileLog(path='/test/new.txt', event_type='new', new_hash='hash789')
        session.add(log)
        session.commit()

        result = session.query(FileLog).first()
        self.assertEqual(result.priority, 'pending')
        session.close()

    def test_file_identity_create(self):
        session = self.Session()
        identity = FileIdentity(
            platform_file_id='1:99',
            current_path='/test/file.txt',
            current_hash='abc123',
            is_active=True,
        )
        session.add(identity)
        session.commit()

        result = session.query(FileIdentity).first()
        self.assertEqual(result.platform_file_id, '1:99')
        self.assertEqual(result.current_path, '/test/file.txt')
        self.assertTrue(result.is_active)
        session.close()

    def test_scan_session_create(self):
        session = self.Session()
        scan = ScanSession(root_path='/test', trigger='manual_scan', status='queued')
        session.add(scan)
        session.commit()

        result = session.query(ScanSession).first()
        self.assertEqual(result.root_path, '/test')
        self.assertEqual(result.trigger, 'manual_scan')
        self.assertEqual(result.status, 'queued')
        session.close()

    def test_analysis_cache_create(self):
        session = self.Session()
        cache = AnalysisCache(
            cache_key='key123',
            content_hash='hash123',
            context_hash='',
            event_type='new',
            verdict_json={'risk_score': 1, 'priority': 'info'},
        )
        session.add(cache)
        session.commit()

        result = session.query(AnalysisCache).first()
        self.assertEqual(result.cache_key, 'key123')
        self.assertEqual(result.verdict_json['priority'], 'info')
        session.close()


class TestScanner(unittest.TestCase):
    """Tests for the scanner module."""

    def setUp(self):
        # Create a temp directory with test files
        self.test_dir = tempfile.mkdtemp()
        self.file1 = os.path.join(self.test_dir, 'test1.txt')
        self.file2 = os.path.join(self.test_dir, 'test2.txt')
        with open(self.file1, 'w') as f:
            f.write('File one content')
        with open(self.file2, 'w') as f:
            f.write('File two content')

    def tearDown(self):
        import shutil
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_walk_directory(self):
        from core.scanner import _walk_directory
        files = _walk_directory(self.test_dir)
        self.assertEqual(len(files), 2)
        basenames = [os.path.basename(f) for f in files]
        self.assertIn('test1.txt', basenames)
        self.assertIn('test2.txt', basenames)


class TestLLMAnalyzer(unittest.TestCase):
    """Tests for the LLM analyzer fallback logic."""

    def test_score_to_priority(self):
        from core.llm_analyzer import _score_to_priority
        self.assertEqual(_score_to_priority(10), 'critical')
        self.assertEqual(_score_to_priority(9), 'critical')
        self.assertEqual(_score_to_priority(7), 'high')
        self.assertEqual(_score_to_priority(5), 'medium')
        self.assertEqual(_score_to_priority(2), 'low')
        self.assertEqual(_score_to_priority(1), 'info')
        self.assertEqual(_score_to_priority(0), 'info')

    def test_fallback_analysis_executable(self):
        from core.llm_analyzer import _fallback_analysis
        result = _fallback_analysis('/test/malware.exe', 'new', 'test')
        self.assertEqual(result['priority'], 'high')
        self.assertGreater(result['risk_score'], 5)

    def test_fallback_analysis_log_file(self):
        from core.llm_analyzer import _fallback_analysis
        result = _fallback_analysis('/var/log/app.log', 'modified', 'test')
        self.assertEqual(result['priority'], 'low')


if __name__ == '__main__':
    unittest.main()
