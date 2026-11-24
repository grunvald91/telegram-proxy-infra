import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import fi_dns_db_stage as stage

class MigrationStageTests(unittest.TestCase):
    def test_atomic_ledger(self):
        rows={name:b"-- reviewed\nBEGIN;\nDO $$ BEGIN NULL; END $$;\nCOMMIT;\n" for name in stage.MIGRATIONS}
        sql=stage.compose(rows)
        self.assertEqual(sql.splitlines().count("BEGIN;"),1)
        self.assertEqual(sql.splitlines().count("COMMIT;"),1)
        self.assertEqual(sql.count("DO $$ BEGIN NULL; END $$;"),3)
        self.assertEqual(sql.count("INSERT INTO public.deployment_schema_migrations"),3)
        self.assertIn("FI gate must remain off",sql)
        self.assertIn("lock_timeout",sql)
    def test_bad_input(self):
        with self.assertRaises(RuntimeError): stage.compose({})
        rows={name:b"BEGIN;\nCOMMIT;\n" for name in stage.MIGRATIONS}
        rows[stage.MIGRATIONS[0]]=b"BEGIN;\nBEGIN;\nCOMMIT;\n"
        with self.assertRaises(RuntimeError): stage.compose(rows)
    def test_fixed_file_names(self):
        with self.assertRaises(RuntimeError): stage.ledger_sql("other.sql")
        for name in stage.MIGRATIONS:
            self.assertIn(name,stage.ledger_sql(name))
