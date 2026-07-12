"""Test path migration from legacy to new structure."""

import os
import tempfile
import shutil
from common import paths


class TestPathMigration:
    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.old_paths = paths
    
    def teardown_method(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)
    
    def test_migrate_db(self):
        """Test migrating chat.db from data/ to data/database/."""
        # Create legacy file
        legacy_db = os.path.join(self.tmpdir, "data", "chat.db")
        os.makedirs(os.path.dirname(legacy_db), exist_ok=True)
        with open(legacy_db, "w") as f:
            f.write("test")

        # Temporarily override paths
        import common.paths as p
        orig_data = p.DATA_DIR
        orig_db = p.DB_PATH
        orig_legacy = p.LEGACY_DB_PATH
        try:
            p.DATA_DIR = os.path.join(self.tmpdir, "data")
            p.DB_PATH = os.path.join(self.tmpdir, "data", "database", "chat.db")
            p.LEGACY_DB_PATH = legacy_db
            msgs = p.migrate_legacy_paths()
            assert any("Migrated" in m for m in msgs)
            assert os.path.exists(p.DB_PATH)
        finally:
            p.DATA_DIR = orig_data
            p.DB_PATH = orig_db
            p.LEGACY_DB_PATH = orig_legacy
