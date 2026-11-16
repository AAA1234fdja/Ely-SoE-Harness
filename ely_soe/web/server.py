"""
Threaded HTTP Server for the ELY Security Lab & SOE Command Center.

Designed specifically for sandbox & cloud preview compatibility:
  - Binds to `0.0.0.0` by default.
  - Accepts reverse-proxied Host & Origin headers without host-allowlist breakage.
  - Serves static assets cleanly with iframe-embedding-friendly headers.
  - Exposes REST JSON API under `/api/...` and serves `index.html` at `/`.
"""

from __future__ import annotations

import json
import mimetypes
import traceback
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from ely_soe.web.api_handlers import SOEApiController


STATIC_DIR = Path(__file__).resolve().parent / "static"


class SOECommandCenterServer(ThreadingHTTPServer):
    """Multi-threaded HTTP server carrying a shared `SOEApiController`."""

    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        controller: SOEApiController,
    ) -> None:
        self.controller = controller
        super().__init__(server_address, SOERequestHandler)


class SOERequestHandler(BaseHTTPRequestHandler):
    """Routes `/api/*` REST calls and serves static dark-mode Command Center UI."""

    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Concise structured request log
        print(f"[ELY-SOE-WEB] {self.address_string()} {format % args}", flush=True)

    @property
    def controller(self) -> SOEApiController:
        return self.server.controller  # type: ignore[attr-defined]

    def _send_common_headers(self, content_type: str, content_length: int, extra: Optional[Dict[str, str]] = None) -> None:
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(content_length))
        self.send_header("Cache-Control", "no-store")
        # Preview & proxy-friendly CORS + iframe embedding support
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Accept")
        if extra:
            for k, v in extra.items():
                self.send_header(k, v)

    def _send_json(self, data: Any, status: int = HTTPStatus.OK) -> None:
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self._send_common_headers("application/json; charset=utf-8", len(body))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(
        self,
        content: str,
        content_type: str,
        status: int = HTTPStatus.OK,
        download_filename: Optional[str] = None,
    ) -> None:
        body = content.encode("utf-8")
        extra = {}
        if download_filename:
            extra["Content-Disposition"] = f'attachment; filename="{download_filename}"'
        self.send_response(status)
        self._send_common_headers(content_type, len(body), extra=extra)
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        if length <= 0:
            return {}
        if length > 2_000_000:
            raise ValueError("Request payload exceeds 2 MB safety limit")
        raw = self.rfile.read(length)
        if not raw.strip():
            return {}
        parsed = json.loads(raw.decode("utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("JSON body must be an object")
        return parsed

    def do_OPTIONS(self) -> None:
        self.send_response(HTTPStatus.NO_CONTENT)
        self._send_common_headers("text/plain", 0)
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path
        qs = parse_qs(parsed.query)

        try:
            if path == "/api/health":
                self._send_json(self.controller.get_health())
                return
            if path == "/api/overview":
                self._send_json(self.controller.get_overview())
                return
            if path == "/api/runs":
                limit = int(qs.get("limit", ["50"])[0])
                self._send_json(self.controller.list_runs(limit=limit))
                return
            if path.startswith("/api/runs/"):
                run_id = path[len("/api/runs/") :].strip("/")
                self._send_json(self.controller.get_run_detail(run_id))
                return
            if path == "/api/compare":
                base_v = qs.get("baseline", [""])[0]
                cand_v = qs.get("candidate", [""])[0]
                self._send_json(self.controller.compare_versions(base_v, cand_v))
                return
            if path == "/api/schedules":
                self._send_json(self.controller.list_schedules())
                return
            if path == "/api/benchmarks":
                self._send_json(self.controller.list_benchmarks())
                return
            if path == "/api/cyber/catalog":
                self._send_json(self.controller.cyber_h2.get_cyber_catalog())
                return
            if path == "/api/h2/catalog":
                self._send_json(self.controller.cyber_h2.get_h2_catalog())
                return
            if path == "/api/h2/latest-sarif":
                content, ctype, fname = self.controller.cyber_h2.export_latest_h2_sarif()
                self._send_text(content, ctype, download_filename=fname)
                return
            if path.startswith("/api/export/"):
                parts = path[len("/api/export/") :].strip("/").split("/")
                if len(parts) != 2:
                    self._send_json({"error": "Expected /api/export/{run_id}/{format}"}, HTTPStatus.BAD_REQUEST)
                    return
                content, ctype, fname = self.controller.export_report(parts[0], parts[1])
                self._send_text(content, ctype, download_filename=fname)
                return

            # Static UI routes
            self._serve_static(path)
        except KeyError as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
        except PermissionError as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        except (ValueError, FileNotFoundError) as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            self._send_json(
                {"error": str(exc), "trace": traceback.format_exc(limit=4)},
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            body = self._read_json_body()
            if path == "/api/audits/run":
                self._send_json(self.controller.run_audit(body))
                return
            if path == "/api/schedules":
                self._send_json(self.controller.create_schedule(body), HTTPStatus.CREATED)
                return
            if path == "/api/schedules/run-due":
                self._send_json(self.controller.trigger_due_schedules(force_all=bool(body.get("force_all", True))))
                return
            if path == "/api/benchmarks/run":
                self._send_json(self.controller.run_benchmark(body))
                return
            if path == "/api/frontier/policy-verify":
                self._send_json(self.controller.run_formal_policy_verification(body))
                return
            if path == "/api/frontier/memory-forensics":
                self._send_json(self.controller.run_memory_forensics_demo(body))
                return
            if path == "/api/frontier/mcp-audit":
                self._send_json(self.controller.run_mcp_audit(body))
                return
            if path == "/api/frontier/guardrail-diff":
                self._send_json(self.controller.run_guardrail_differential(body))
                return
            if path == "/api/frontier/policy-synthesize":
                self._send_json(self.controller.run_policy_synthesis(body))
                return
            if path == "/api/frontier/purple-replay":
                self._send_json(self.controller.run_purple_team_replay(body))
                return
            if path == "/api/frontier/patch-verify":
                self._send_json(self.controller.run_patch_verification(body))
                return
            if path == "/api/demo/seed":
                self._send_json(self.controller.seed_demo_workspace())
                return
            if path == "/api/cyber/scan":
                self._send_json(self.controller.cyber_h2.run_cyber_scan(body))
                return
            if path == "/api/cyber/enterprise-sim":
                self._send_json(self.controller.cyber_h2.run_enterprise_sim(body))
                return
            if path == "/api/cyber/soar-execute":
                self._send_json(self.controller.cyber_h2.run_soar_playbook(body))
                return
            if path == "/api/cyber/sigma-hunt":
                self._send_json(self.controller.cyber_h2.run_sigma_yara_hunt(body))
                return
            if path == "/api/cyber/cicd-audit":
                self._send_json(self.controller.cyber_h2.run_cicd_ppe_audit(body))
                return
            if path == "/api/h2/study":
                self._send_json(self.controller.cyber_h2.run_h2_complete_study(body))
                return
            if path == "/api/h2/ab-lift":
                self._send_json(self.controller.cyber_h2.run_h2_ab_lift(body))
                return
            if path == "/api/h2/curriculum-bench":
                self._send_json(self.controller.cyber_h2.run_h2_curriculum_bench(body))
                return
            if path == "/api/h2/adversarial-stress":
                self._send_json(self.controller.cyber_h2.run_h2_adversarial_stress(body))
                return
            if path == "/api/h2/fleet-sweep":
                self._send_json(self.controller.cyber_h2.run_h2_fleet_sweep(body))
                return
            if path == "/api/h2/adtree-solve":
                self._send_json(self.controller.cyber_h2.run_h2_adtree_solve(body))
                return

            self._send_json({"error": f"Unknown endpoint `{path}`"}, HTTPStatus.NOT_FOUND)
        except KeyError as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.NOT_FOUND)
        except PermissionError as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.FORBIDDEN)
        except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
            self._send_json({"error": str(exc)}, HTTPStatus.BAD_REQUEST)
        except Exception as exc:
            self._send_json(
                {"error": str(exc), "trace": traceback.format_exc(limit=4)},
                HTTPStatus.INTERNAL_SERVER_ERROR,
            )

    def _serve_static(self, req_path: str) -> None:
        rel = "index.html" if req_path in ("", "/") else req_path.lstrip("/")
        if rel.startswith("static/"):
            rel = rel[len("static/") :]
        target = (STATIC_DIR / rel).resolve()
        if not target.is_relative_to(STATIC_DIR) or not target.exists() or not target.is_file():
            # SPA fallback to index.html
            target = STATIC_DIR / "index.html"
        content = target.read_bytes()
        ctype, _ = mimetypes.guess_type(str(target))
        if not ctype:
            ctype = "application/octet-stream"
        if ctype.startswith("text/") or ctype.endswith("javascript"):
            ctype = f"{ctype}; charset=utf-8"
        self.send_response(HTTPStatus.OK)
        self._send_common_headers(ctype, len(content))
        self.end_headers()
        self.wfile.write(content)


def create_server(
    host: str = "0.0.0.0",
    port: int = 8080,
    controller: Optional[SOEApiController] = None,
    seed_demo: bool = True,
) -> SOECommandCenterServer:
    ctrl = controller if controller is not None else SOEApiController()
    if seed_demo:
        ctrl.seed_demo_workspace()
    return SOECommandCenterServer((host, port), ctrl)
