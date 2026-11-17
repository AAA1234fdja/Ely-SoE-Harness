"""
Tests for Layer 8 (`ely_soe.web` REST API + Command Center UI) and Layer 9 (`ely_soe.cli`).

Starts a real threaded `SOECommandCenterServer` on an ephemeral OS port, sends genuine
HTTP GET/POST requests across all API routes, validates scope enforcement on web audits,
multi-format report downloads (JSON, Markdown, SARIF, HTML, MITRE ATLAS), and tests
key `ely-soe` CLI subcommands!
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from ely_soe.cli import main as cli_main
from ely_soe.core.config import SOEConfig
from ely_soe.soe.engine import SecurityOrchestrationEngine
from ely_soe.web.api_handlers import SOEApiController
from ely_soe.web.server import SOECommandCenterServer


class TestWebCommandCenterAndCLI(unittest.TestCase):
    """End-to-end HTTP REST API, Static UI, ScopeGuard, and CLI tests."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        cfg = SOEConfig(data_dir=self._tmp.name)
        cfg.validator.reproducibility_trials = 1
        cfg.fuzzer.max_iterations_per_target = 40
        soe = SecurityOrchestrationEngine(config=cfg)
        self.controller = SOEApiController(soe=soe, repo_root=Path.cwd())
        self.server = SOECommandCenterServer(("127.0.0.1", 0), self.controller)
        self.port = self.server.server_address[1]
        self.base_url = f"http://127.0.0.1:{self.port}"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self._thread.join(timeout=3)
        self._tmp.cleanup()

    def _get(self, path: str) -> tuple[int, str, str]:
        with urllib.request.urlopen(f"{self.base_url}{path}", timeout=30) as resp:
            return resp.status, resp.headers.get("Content-Type", ""), resp.read().decode("utf-8")

    def _post_json(self, path: str, payload: dict) -> tuple[int, dict]:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}{path}",
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))

    def test_static_ui_health_and_frontier_endpoints(self) -> None:
        # 1. Static HTML / CSS / JS assets load cleanly
        st, ctype, html = self._get("/")
        self.assertEqual(st, 200)
        self.assertIn("text/html", ctype)
        self.assertIn("ELY Security Lab", html)

        st_js, _, js = self._get("/static/app.js")
        self.assertEqual(st_js, 200)
        # Ensure browser code NEVER calls localhost or 127.0.0.1!
        self.assertNotIn("http://localhost", js)
        self.assertNotIn("http://127.0.0.1", js)

        # 2. Health endpoint
        st_h, _, raw_h = self._get("/api/health")
        self.assertEqual(st_h, 200)
        health = json.loads(raw_h)
        self.assertEqual(health["status"], "ok")
        self.assertIn("glm-5.3", health["models_available"])

        # 3. Frontier Workbench live endpoints
        st_pv, pv = self._post_json("/api/frontier/policy-verify", {"mode": "hardened"})
        self.assertEqual(st_pv, 200)
        self.assertTrue(pv["all_theorems_hold"])

        st_mf, mf = self._post_json("/api/frontier/memory-forensics", {})
        self.assertEqual(st_mf, 200)
        self.assertGreaterEqual(mf["quarantined_count"], 2)

        st_mcp, mcp = self._post_json("/api/frontier/mcp-audit", {"target_root": "v0_9"})
        self.assertEqual(st_mcp, 200)
        self.assertGreaterEqual(len(mcp["findings"]), 4)

        st_pt, pt = self._post_json(
            "/api/frontier/purple-replay",
            {"target_root": "v1_0_hardened", "baseline_target_root": "v0_9"},
        )
        self.assertEqual(st_pt, 200)
        self.assertEqual(pt["resilience_score"], 100.0)

    def test_audit_execution_scope_blocking_and_report_exports(self) -> None:
        # ScopeGuard MUST block external path traversal via HTTP API (403 Forbidden)
        req = urllib.request.Request(
            f"{self.base_url}/api/audits/run",
            data=json.dumps({"target_root": "/etc"}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req, timeout=10)
        self.assertEqual(ctx.exception.code, 403)

        # Authorized lab target succeeds
        st, res = self._post_json(
            "/api/audits/run",
            {
                "target_root": "lab_targets/ely_specimen/v0_9",
                "target_version": "0.9.0-web",
                "modality": "on_demand",
                "domains": ["tool_execution", "rust_core"],
            },
        )
        self.assertEqual(st, 200)
        run_id = res["run_id"]
        self.assertGreater(len(res["report"]["findings"]), 0)

        # Multi-format exports all return 200
        for fmt in ("json", "markdown", "sarif", "html", "atlas"):
            st_e, _, body_e = self._get(f"/api/export/{run_id}/{fmt}")
            self.assertEqual(st_e, 200)
            self.assertGreater(len(body_e), 40)

    def test_cli_frontier_and_pre_release_exit_codes(self) -> None:
        with tempfile.TemporaryDirectory() as cli_tmp:
            # Hardened policy verification returns 0
            rc_ok = cli_main(["--data-dir", cli_tmp, "frontier", "policy-verify", "--mode", "hardened"])
            self.assertEqual(rc_ok, 0)

            # Vulnerable policy verification returns 2
            rc_fail = cli_main(["--data-dir", cli_tmp, "frontier", "policy-verify", "--mode", "vulnerable"])
            self.assertEqual(rc_fail, 2)

            # Pre-release gate on v0.9 returns 2 (BLOCKED)
            rc_v09 = cli_main(["--data-dir", cli_tmp, "pre-release", "lab_targets/ely_specimen/v0_9", "--version", "0.9.0"])
            self.assertEqual(rc_v09, 2)

            # Pre-release gate on v1.0_hardened returns 0 (APPROVED)
            rc_v10 = cli_main(
                [
                    "--data-dir",
                    cli_tmp,
                    "pre-release",
                    "lab_targets/ely_specimen/v1_0_hardened",
                    "--version",
                    "1.0.0-rc1",
                    "--previous-version",
                    "0.9.0",
                ]
            )
            self.assertEqual(rc_v10, 0)


if __name__ == "__main__":
    unittest.main()
