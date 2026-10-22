import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
CORPUS = ROOT / "research" / "experiments" / "split_bypass"
MANIFEST = CORPUS / "manifest.json"


class SplitBypassCorpusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads(MANIFEST.read_text())

    def test_manifest_ids_are_unique(self):
        ids = [row["program_id"] for row in self.manifest["programs"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertGreaterEqual(len(ids), 5)

    def test_each_manifest_source_exists(self):
        for row in self.manifest["programs"]:
            with self.subTest(program_id=row["program_id"]):
                self.assertTrue((CORPUS / row["source"]).is_file())

    def test_oracle_results_are_not_fabricated(self):
        for row in self.manifest["programs"]:
            with self.subTest(program_id=row["program_id"]):
                self.assertIsNone(row["reference_verdict"])
                self.assertIsNone(row["reference_evidence"])
                self.assertIsNone(row["object_sha256"])
                self.assertEqual(row["status"], "pending_compile_and_reference_run")

    def test_manifest_declares_source_only_status(self):
        self.assertEqual(
            self.manifest["status"],
            "source_fixtures_not_yet_compiled_or_oracle_verified",
        )

    def test_runner_writes_to_isolated_results_directory(self):
        runner = (CORPUS / "run_corpus.py").read_text()
        self.assertIn("results/split-bypass-evaluation", runner)
        self.assertIn("refusing to overwrite existing run directory", runner)
        self.assertIn("block-level verification are inferred", runner)

    def test_all_fixtures_declare_xdp_program_and_license(self):
        for row in self.manifest["programs"]:
            source = (CORPUS / row["source"]).read_text()
            with self.subTest(program_id=row["program_id"]):
                self.assertIn('SEC("xdp")', source)
                self.assertIn('SEC("license")', source)


if __name__ == "__main__":
    unittest.main()
