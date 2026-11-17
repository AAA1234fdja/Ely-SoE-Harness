"""Integration tests for CLI cyber/h2 subcommands and /api/cyber/* + /api/h2/* REST API controller."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

from ely_soe.web.cyber_h2_api import CyberAndHarness2ApiController

REPO_ROOT = Path(__file__).resolve().parents[1]


class TestCLIAndWebCyberH2(unittest.TestCase):
    def test_web_api_controller_cyber_and_h2_endpoints(self) -> None:
        api = CyberAndHarness2ApiController(repo_root=REPO_ROOT)

        c_cat = api.get_cyber_catalog()
        self.assertGreaterEqual(c_cat["total_specialized_engines"], 47)

        h_cat = api.get_h2_catalog()
        self.assertGreaterEqual(h_cat["total_meta_subsystems"], 27)
        self.assertGreaterEqual(h_cat["registered_first_order_stages_count"], 34)

        # ScopeGuard path confinement rejects traversal outside repo root
        with self.assertRaises(PermissionError):
            api.run_cyber_scan({"target_path": "/etc/passwd"})

        scan = api.run_cyber_scan({"target_path": "lab_targets/ely_specimen/v0_9"})
        self.assertEqual(scan["gate_verdict"], "BLOCKED")

        sim = api.run_enterprise_sim({"hardened": False})
        self.assertGreater(sim["fair_financial_risk"]["mean_ale_usd"], 1_000_000.0)

        soar = api.run_soar_playbook({"playbook_id": "PB-RANSOMWARE-ISOLATION", "dry_run": True})
        self.assertTrue(soar["ledger_verified"])

        sigma = api.run_sigma_yara_hunt({})
        self.assertGreater(sigma["sigma_hunt"]["alerts_triggered"], 0)
        self.assertGreater(len(sigma["yara_scan"]["yara_matches"]), 0)

        cicd = api.run_cicd_ppe_audit({})
        self.assertGreaterEqual(cicd["total_findings"], 2)

        study = api.run_h2_complete_study({"target_path": "lab_targets/ely_specimen/v0_9", "profile": "fast_ci"})
        self.assertEqual(study["formal_meta_verification"]["overall_verdict"], "PROVEN_SAFE")

        sarif_text, ctype, fname = api.export_latest_h2_sarif()
        self.assertIn("sarif+json", ctype)
        self.assertTrue(fname.endswith(".sarif.json"))
        sarif = json.loads(sarif_text)
        self.assertEqual(sarif["version"], "2.1.0")

        adtree = api.run_h2_adtree_solve({"defense_budget_usd": 35000})
        self.assertLessEqual(adtree["optimal_defense_spend_usd"], 35000.0)

    def test_cli_cyber_and_h2_subcommands_json_output(self) -> None:
        for cmd in (
            [sys.executable, "-m", "ely_soe", "cyber", "catalog", "--json"],
            [sys.executable, "-m", "ely_soe", "cyber", "soar", "--playbook", "PB-RANSOMWARE-ISOLATION", "--json"],
            [sys.executable, "-m", "ely_soe", "h2", "catalog", "--json"],
            [sys.executable, "-m", "ely_soe", "h2", "stress", "--json"],
        ):
            proc = subprocess.run(cmd, cwd=str(REPO_ROOT), capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 0, msg=f"CLI failed: {cmd}\nSTDERR: {proc.stderr}")
            parsed = json.loads(proc.stdout)
            self.assertIsInstance(parsed, dict)


if __name__ == "__main__":
    unittest.main()
