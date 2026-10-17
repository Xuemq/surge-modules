"""Pinned inputs, exact URL fetching, atomic writes and sanitized update checks."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import tempfile
import urllib.request
from urllib.parse import urlsplit
from .core import Invalid, clean_bytes, digest, merge, parse_module
from .converter import convert_qx

ALLOWED_HOSTS = {"raw.githubusercontent.com", "ddgksf2013.top"}
MAX_BYTES = 8 * 1024 * 1024


def atomic_write(path: Path, data: bytes):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data); f.flush(); os.fsync(f.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def json_write(path, obj):
    atomic_write(Path(path), (json.dumps(obj, ensure_ascii=False, indent=2) + "\n").encode())


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def check_url(url):
    p = urlsplit(url)
    if p.scheme != "https" or p.hostname not in ALLOWED_HOSTS or p.port not in {None, 443} or p.username or p.password or p.query or p.fragment:
        raise Invalid("source URL must be an allowlisted HTTPS URL without credentials/query/fragment")
    if p.hostname == "ddgksf2013.top" and p.path != "/rewrite/StartUpAds.conf":
        raise Invalid("unapproved ddgks source path")
    if p.hostname == "raw.githubusercontent.com" and not (p.path.startswith("/fmz200/wool_scripts/") or p.path.startswith("/blackmatrix7/ios_rule_script/")):
        raise Invalid("unapproved GitHub source repository")


def load_manifest(path):
    m = read_json(path)
    if m.get("schema_version") != 1 or not isinstance(m.get("sources"), list) or not m["sources"]:
        raise Invalid("invalid source manifest")
    ids = set()
    for s in m["sources"]:
        if not re.fullmatch(r"[a-z0-9_-]+", s.get("id", "")) or s["id"] in ids:
            raise Invalid("invalid/duplicate source ID")
        ids.add(s["id"])
        if s.get("format") not in {"surge", "qx"} or not re.fullmatch(r"[a-f0-9]{64}", s.get("sha256", "")):
            raise Invalid("source format/hash missing")
        if not isinstance(s.get("bytes"), int) or not 0 < s["bytes"] <= MAX_BYTES:
            raise Invalid("exact source byte count required")
        check_url(s["url"])
        if s.get("immutable_url"):
            check_url(s["immutable_url"])
    if m.get("base") != m["sources"][0]["id"]:
        raise Invalid("base must be the first source; order is a reviewed behavior decision")
    return m


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Invalid("source redirect blocked; review the manifest URL")


def download(url):
    check_url(url)
    opener = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": "surge-module-auditor/0.1", "Accept": "text/plain"})
    with opener.open(request, timeout=30) as response:
        if response.status != 200 or response.geturl() != url:
            raise Invalid("unexpected source response")
        data = response.read(MAX_BYTES + 1)
        expected = response.headers.get("Content-Length")
        if expected and (not expected.isdecimal() or int(expected) != len(data)):
            raise Invalid("source response size mismatch")
    clean_bytes(data)
    return data


def cache_path(cache, source):
    return Path(cache) / (source["id"] + ".source")


def verify_bytes(source, data):
    clean_bytes(data)
    if len(data) != source["bytes"] or digest(data) != source["sha256"]:
        raise Invalid("source differs from reviewed hash/size; review update instead of overwriting lock")


def fetch(manifest, cache):
    pending = []
    for s in manifest["sources"]:
        data = download(s.get("immutable_url") or s["url"])
        verify_bytes(s, data)
        pending.append((cache_path(cache, s), data))
    # Nothing is replaced until every source passes; each file replacement is atomic.
    for path, data in pending:
        atomic_write(path, data)
    return {"status": "fetched_locked_sources", "sources": [s["id"] for s in manifest["sources"]]}


def audit(manifest, cache, overrides):
    result = {"schema_version": 1, "status": "blocked", "static_only": True, "sources": [], "blockers": []}
    modules = []
    for s in manifest["sources"]:
        info = {"id": s["id"], "sha256": s["sha256"]}
        try:
            path = cache_path(cache, s)
            if not path.is_file():
                raise Invalid("required source is missing; run fetch")
            data = path.read_bytes(); verify_bytes(s, data)
            if s["format"] == "qx":
                converted, conversion = convert_qx(data, manifest.get("conversion_policy"))
                info["conversion"] = conversion
                if converted is None:
                    raise Invalid("QX conversion has unresolved directives; no source was silently skipped")
                data = converted.encode()
            mod = parse_module(data, s["id"])
            modules.append(mod)
            info.update(status="parsed", active_entries=len(mod.entries))
        except (Invalid, OSError) as exc:
            info.update(status="blocked", error=str(exc)); result["blockers"].append(s["id"] + ": " + str(exc))
        result["sources"].append(info)
    result["redistribution_reviewed"] = manifest.get("redistribution", {}).get("approved", False) is True
    if not result["redistribution_reviewed"]:
        result["publication_blocked"] = "Upstream redistribution/license compatibility has not been approved. Local analysis only."
    if result["blockers"]:
        return None, result
    candidate, report = merge(modules, overrides)
    result["merge"] = report
    if candidate is None:
        result["blockers"].append("Unresolved merge conflicts")
        return None, result
    result["status"] = "candidate_static_pass"
    return candidate, result


def check_updates(manifest):
    result = {"schema_version": 1, "status": "unchanged", "sources": [], "blockers": []}
    for s in manifest["sources"]:
        info = {"id": s["id"], "expected_sha256": s["sha256"]}
        try:
            data = download(s["url"])
            current = digest(data)
            info.update(status="unchanged" if current == s["sha256"] and len(data) == s["bytes"] else "changed", sha256=current, bytes=len(data))
            if info["status"] == "changed":
                result["status"] = "changed"
        except Exception:
            # Never echo remote text, URLs or arbitrary exception strings to public logs.
            info.update(status="error", error="Fetch/format validation failed; inspect locally.")
            result["blockers"].append(s["id"] + ": fetch/format validation failed")
        result["sources"].append(info)
    if not manifest.get("redistribution", {}).get("approved", False):
        result["blockers"].append("Redistribution/license review is pending")
    if not manifest.get("conversion_policy", {}).get("reviewed", False):
        result["blockers"].append("QX conversion/runtime compatibility review is pending")
    if result["blockers"]:
        result["status"] = "blocked"
    return result
