"""Read the Container artifact stamp without treating Worker environment as build proof."""

import os
import re
from pathlib import Path

import requests


def container_release():
    path = Path(__file__).resolve().parent.parent / ".container-build-id"
    try:
        value = path.read_text().strip()
    except OSError:
        value = ""
    return {"build_id": value if re.fullmatch(r"[a-f0-9]{64}", value) else None,
            "compatibility": 1, "storage": "postgresql" if os.environ.get("CONTROL_PLANE_DATABASE_URL", "").strip() else "sqlite",
            "durability_warning": None if os.environ.get("CONTROL_PLANE_DATABASE_URL", "").strip() else "Container-local SQLite may be lost on replacement. Configure durable storage before rollout."}


def deployment_status(worker):
    container = container_release()
    expected = worker.get("build_id")
    actual = container["build_id"]
    match = bool(expected and actual and expected == actual and worker.get("compatibility") == container["compatibility"])
    return {"worker": worker, "container": container,
            "state": "matched" if match else "pending_or_mixed" if actual and expected else "unverified",
            "message": "Worker and Container source fingerprints match" if match else "A full matching build/deployment has not been verified"}


def compatibility_probes(origin):
    results = []
    with requests.Session() as client:
        client.trust_env = False
        for path, method in (("/ready", "GET"), ("/v1/chat/completions", "OPTIONS"), ("/roleplay/v1/chat/completions", "OPTIONS")):
            try:
                response = client.request(method, origin + path, timeout=(5, 10), stream=True, allow_redirects=False,
                                          headers={"Origin": "https://janitorai.com", "Access-Control-Request-Method": "POST",
                                                   "Access-Control-Request-Headers": "authorization,content-type"})
                with response:
                    allowed = response.headers.get("Access-Control-Allow-Origin")
                    methods = response.headers.get("Access-Control-Allow-Methods", "").upper()
                    headers = response.headers.get("Access-Control-Allow-Headers", "").lower()
                    passed = response.status_code == 200 if method == "GET" else (
                        response.status_code in (200, 204) and allowed in ("https://janitorai.com", "*")
                        and "POST" in methods and "authorization" in headers and "content-type" in headers)
                    results.append({"path": path, "method": method, "status": response.status_code, "passed": passed})
            except requests.RequestException:
                results.append({"path": path, "method": method, "status": None, "passed": False})
    return {"scope": "server-to-Worker checks; not proof of the browser network path or model generation", "checks": results}
