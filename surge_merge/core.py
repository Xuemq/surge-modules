"""Original conservative parser. This is not the Surge runtime/regex engine."""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import hashlib
import json
import re
from urllib.parse import urlsplit, parse_qsl

SECTIONS = ("General", "Rule", "URL Rewrite", "Header Rewrite", "Body Rewrite", "Map Local", "Script", "MITM")
RULE_TYPES = {"DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD", "IP-CIDR", "IP-CIDR6", "URL-REGEX", "USER-AGENT", "AND", "OR", "NOT"}
POLICIES = {"DIRECT", "REJECT", "REJECT-TINYGIF", "REJECT-DROP", "REJECT-NO-DROP"}
SEMANTIC_METADATA = {"system", "requirement", "arguments", "arguments-desc"}
SECRET_KEYS = re.compile(r"(?i)(?:^|[\s,])(?:ca-p12|ca-passphrase|password|passwd|private-key|api-key|access-token|auth-token|managed-config|external-controller-access|http-api|socks5-auth)\s*=")
URLS = re.compile(r"https?://[^\s\"'<>]+")

class Invalid(ValueError):
    pass

def digest(value: str | bytes) -> str:
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()

def security_scan(text: str) -> None:
    if SECRET_KEYS.search(text) or re.search(r"-----BEGIN (?:[A-Z ]*PRIVATE KEY|CERTIFICATE)-----", text):
        raise Invalid("credential or main-profile material detected (content redacted)")
    for token in URLS.findall(text):
        if re.match(r"https?://[^/\s]+@", token):
            raise Invalid("credential-bearing URL detected (content redacted)")
        try:
            parsed = urlsplit(token)
        except ValueError:
            # Regex URL patterns may contain bracket expressions, not IPv6 hosts.
            # Detect sensitive queries separately even when the URL is a regex.
            query = token.partition("?")[2]
            if any(re.search(r"(?i)^(?:token|access_token|api_?key|password|auth|secret|subscription)$", k) for k, _ in parse_qsl(query)):
                raise Invalid("sensitive URL query detected (content redacted)")
            continue
        if parsed.username or parsed.password:
            raise Invalid("credential-bearing URL detected (content redacted)")
        if any(re.search(r"(?i)^(?:token|access_token|api_?key|password|auth|secret|subscription)$", k) for k, _ in parse_qsl(parsed.query)):
            raise Invalid("sensitive URL query detected (content redacted)")

def clean_bytes(data: bytes) -> str:
    if not data or len(data) > 8 * 1024 * 1024:
        raise Invalid("empty or oversized source")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeError as exc:
        raise Invalid("source is not UTF-8") from exc
    if re.search(r"(?i)<(?:!doctype\s+html|html|head|body)(?:\s|>)", text[:4096]):
        raise Invalid("HTML/error response is not a source")
    if any(ord(c) < 32 and c not in "\n\r\t" for c in text):
        raise Invalid("control character in source")
    security_scan(text)
    return text

def split_fields(text: str, delimiter: str = ",", nesting: bool = False) -> list[str]:
    """Split without decoding escapes or treating regex commas as separators."""
    parts, start, quote, depth = [], 0, None, 0
    for i, c in enumerate(text):
        escaped = i > 0 and len(text[:i]) - len(text[:i].rstrip("\\")) & 1
        if quote:
            if c == quote and not escaped:
                quote = None
        elif c in "\"'" and (i == 0 or text[i-1] in " =,\t"):
            quote = c
        elif nesting and not escaped and c in "([{":
            depth += 1
        elif nesting and not escaped and c in ")]}":
            depth -= 1
            if depth < 0:
                raise Invalid("unbalanced field delimiters")
        elif c == delimiter and depth == 0:
            parts.append(text[start:i].strip()); start = i + 1
    if quote or depth:
        raise Invalid("unclosed quote or field delimiters")
    parts.append(text[start:].strip())
    return parts

def words(text: str) -> list[str]:
    """Whitespace lexer that retains quotes/backslashes exactly."""
    out, start, quote = [], None, None
    for i, c in enumerate(text):
        escaped = i > 0 and (len(text[:i]) - len(text[:i].rstrip("\\"))) % 2
        if start is None:
            if c.isspace():
                continue
            start = i
            if c in "\"'":
                quote = c
        elif quote:
            if c == quote and not escaped:
                quote = None
        elif c in "\"\'" and i > 0 and text[i-1] == "=":
            quote = c
        elif c.isspace():
            out.append(text[start:i]); start = None
    if quote:
        raise Invalid("unclosed quoted token")
    if start is not None:
        out.append(text[start:])
    return out

def unquote(s: str) -> str:
    return s[1:-1] if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'" else s

def params(text: str) -> dict[str, str]:
    # A comma is a parameter separator only when followed by a key= pair.
    fields = re.split(r",\s*(?=[a-z][a-z0-9-]*\s*=)", text)
    out = {}
    for part in fields:
        key, sep, val = part.partition("=")
        key, val = key.strip(), val.strip()
        if not sep or not val or key in out or not re.fullmatch(r"[a-z][a-z0-9-]*", key):
            raise Invalid("malformed/duplicate script parameter")
        out[key] = unquote(val)
    return out

@dataclass(frozen=True)
class Entry:
    section: str
    raw: str
    source: str
    line: int
    key: str
    pattern: str | None = None
    phase: str | None = None
    safe_dedup: bool = True
    @property
    def id(self) -> str:
        return digest(self.section + "\0" + self.raw)
    def ref(self) -> dict:
        return {"id": self.id, "source": self.source, "line": self.line, "section": self.section}

@dataclass
class Module:
    source: str
    entries: list[Entry] = field(default_factory=list)
    metadata: dict[str, str] = field(default_factory=dict)

def parse_entry(section: str, raw: str, source: str, line: int) -> Entry:
    key, pattern, phase, safe = "", None, None, True
    if section == "Rule":
        f = split_fields(raw, nesting=True)
        if len(f) < 3 or f[0] not in RULE_TYPES or not f[1] or f[2] not in POLICIES or any(v not in {"no-resolve", "extended-matching", "pre-matching"} for v in f[3:]):
            raise Invalid("unsupported or malformed Rule (external rule sets/custom policies forbidden)")
        key = f[0] + "," + f[1]
    elif section == "Script":
        name, eq, body = raw.partition("=")
        if not eq or not name.strip():
            raise Invalid("Script requires a label")
        p = params(body)
        if p.get("type") not in {"http-request", "http-response"} or not p.get("pattern") or not p.get("script-path"):
            raise Invalid("only named HTTP scripts with pattern/script-path are supported")
        u = urlsplit(p["script-path"])
        if u.scheme != "https" or not u.netloc or u.username or u.password:
            raise Invalid("script-path must be an HTTPS URL; local scripts are unsupported")
        if set(p) - {"type", "pattern", "script-path", "requires-body", "binary-body-mode", "timeout", "max-size", "script-update-interval", "argument", "engine", "debug", "enabled"}:
            raise Invalid("unsupported script parameter")
        key, pattern, phase = name.strip(), p["pattern"], p["type"]
    elif section in {"MITM", "General"}:
        key, eq, value = raw.partition("=")
        key, value = key.strip(), value.strip()
        allowed = {"hostname"} if section == "MITM" else {"force-http-engine-hosts"}
        if not eq or key not in allowed or not value:
            raise Invalid("unsupported setting; main config/security settings are forbidden")
        host_list(value)  # preserve append/insert/replace and signed wildcard ordering
    else:
        w = words(raw)
        if section == "URL Rewrite":
            if len(w) not in {2, 3} or (len(w) == 3 and w[2] not in {"reject", "302", "307", "header"}):
                raise Invalid("malformed URL Rewrite")
            key = pattern = unquote(w[0]); phase = "http-request"
            safe = len(w) == 3 and w[2] == "reject"
        elif section == "Map Local":
            if len(w) < 2 or not any(t.startswith("data-type=") for t in w[1:]):
                raise Invalid("Map Local requires explicit data-type")
            allowed = {"data-type", "data", "status-code", "header"}
            for token in w[1:]:
                k, sep, v = token.partition("=")
                if not sep or k not in allowed or not v:
                    raise Invalid("malformed Map Local parameter")
                if k == "data-type" and v not in {"text", "base64", "tiny-gif"}:
                    raise Invalid("remote/local file mapping requires separate review")
            key = pattern = unquote(w[0]); phase = "http-request"
        elif section == "Header Rewrite":
            if w and w[0] not in {"http-request", "http-response"}:
                w.insert(0, "http-request")
            if len(w) < 4 or w[2] not in {"header-add", "header-del", "header-replace", "header-replace-regex"}:
                raise Invalid("malformed Header Rewrite")
            count = {"header-add": 5, "header-del": 4, "header-replace": 5, "header-replace-regex": 6}[w[2]]
            if len(w) != count:
                raise Invalid("malformed Header Rewrite parameters")
            pattern, phase = unquote(w[1]), w[0]
            key, safe = phase + " " + pattern + " " + w[3], False
        elif section == "Body Rewrite":
            if not w or w[0] not in {"http-request", "http-response", "http-request-jq", "http-response-jq"}:
                raise Invalid("unsupported Body Rewrite direction")
            if (w[0].endswith("-jq") and len(w) != 3) or (not w[0].endswith("-jq") and (len(w) < 4 or len(w) % 2)):
                raise Invalid("malformed Body Rewrite")
            pattern, phase = unquote(w[1]), w[0].removesuffix("-jq")
            key, safe = phase + " " + pattern, False
        else:
            raise Invalid("unsupported section")
    if not key:
        raise Invalid("empty match key")
    return Entry(section, raw, source, line, key, pattern, phase, safe)

def host_list(value: str) -> tuple[str, list[str]]:
    mode = "replace"
    if value.startswith(("%APPEND%", "%INSERT%")):
        mode, value = value.split("%", 2)[1], value.split("%", 2)[2].strip()
    hosts = [h.strip() for h in value.split(",")]
    if not hosts or any(not h or not re.fullmatch(r"-?[A-Za-z0-9_.*?:\[\]-]+", h) for h in hosts):
        raise Invalid("unsupported/empty hostname token")
    return mode, hosts

def parse_module(data: bytes, source: str) -> Module:
    text = clean_bytes(data)
    module, section, seen_sections = Module(source), None, set()
    for n, line in enumerate(text.splitlines(), 1):
        raw = line.strip()
        if not raw:
            continue
        if raw.startswith("#!"):
            if section:
                raise Invalid(f"{source}:{n}: mid-file directives require review")
            k, sep, v = raw[2:].partition("=")
            if not sep:
                raise Invalid(f"{source}:{n}: unsupported metadata directive")
            if k in SEMANTIC_METADATA:
                if k in module.metadata:
                    raise Invalid(f"{source}:{n}: duplicate semantic metadata")
                module.metadata[k] = v
            continue
        if raw.startswith(("#", ";", "//")):
            continue
        if raw.startswith("["):
            if raw not in [f"[{s}]" for s in SECTIONS] or raw in seen_sections:
                raise Invalid(f"{source}:{n}: unsupported/repeated section")
            seen_sections.add(raw); section = raw[1:-1]; continue
        if section is None:
            raise Invalid(f"{source}:{n}: active data outside a section")
        try:
            module.entries.append(parse_entry(section, raw, source, n))
        except Invalid as exc:
            raise Invalid(f"{source}:{n}: {exc}") from exc
    if not module.entries:
        raise Invalid(f"{source}: no active entries")
    declared = set()
    if "arguments" in module.metadata:
        for arg in module.metadata["arguments"].split(","):
            name = arg.split(":", 1)[0]
            if not re.fullmatch(r"[A-Za-z0-9_]+", name) or name in declared:
                raise Invalid(f"{source}: invalid/duplicate argument")
            declared.add(name)
    used = set(re.findall(r"\{\{\{([^{}]+)\}\}\}", "\n".join(e.raw for e in module.entries)))
    if used - declared:
        raise Invalid(f"{source}: undefined module argument")
    return module

def conflict(kind: str, entries: list[Entry], key: str) -> dict:
    refs = [e.ref() for e in entries]
    identity = json.dumps([kind, key, sorted(e.id for e in entries)], ensure_ascii=False)
    return {"id": digest(identity), "kind": kind, "key": key, "entries": refs}

def merge(modules: list[Module], overrides: dict | None = None) -> tuple[str | None, dict]:
    overrides = overrides or {"schema_version": 1, "decisions": []}
    if overrides.get("schema_version") != 1 or not isinstance(overrides.get("decisions"), list):
        raise Invalid("unsupported overrides schema")
    decisions = {}
    for d in overrides["decisions"]:
        if set(d) != {"conflict_id", "entry_ids", "action", "reason"} or d["action"] != "keep" or not d["reason"].strip() or not isinstance(d["entry_ids"], list) or not d["entry_ids"] or d["conflict_id"] in decisions:
            raise Invalid("malformed override: use exact conflict, kept entry IDs and reason")
        decisions[d["conflict_id"]] = d
    all_entries = [e for m in modules for e in m.entries]
    report = {"schema_version": 1, "static_only": True, "sources": [m.source for m in modules], "counts_before": dict(Counter(e.section for e in all_entries)), "duplicates": [], "conflicts": [], "resolved": [], "warnings": ["No regex equivalence/overlap proof; no Surge application validation; referenced scripts are not fetched or executed."]}
    metadata = {}
    for m in modules:
        for k, v in m.metadata.items():
            if k in metadata and metadata[k] != v:
                report["conflicts"].append({"id": digest("metadata:" + k), "kind": "metadata", "key": k, "sources": [x.source for x in modules if k in x.metadata]})
            else:
                metadata[k] = v
    kept, seen_exact = [], {}
    for e in all_entries:
        if e.safe_dedup and e.id in seen_exact:
            report["duplicates"].append({"kept": seen_exact[e.id].ref(), "removed": e.ref()})
        else:
            kept.append(e); seen_exact[e.id] = e
    groups = {}
    for e in kept:
        groups.setdefault((e.section, e.key), []).append(e)
    potential = []
    for (section, key), es in groups.items():
        if len(es) > 1:
            if section in {"MITM", "General"}:
                parsed = [host_list(e.raw.partition("=")[2].strip()) for e in es]
                if len({m for m, _ in parsed}) != 1:
                    potential.append(conflict("host-list-mode", es, key))
                elif any(h.startswith("-") and h[1:] in {x for _, hs in parsed for x in hs} for _, hs in parsed for h in hs):
                    potential.append(conflict("host-list-exclusion", es, key))
            elif section in {"Body Rewrite", "Header Rewrite"} and len({e.source for e in es}) == 1:
                # Within-source sequential transformations are deliberate and retained.
                report["warnings"].append(f"Preserved sequential {section} entries from {es[0].source}.")
            else:
                potential.append(conflict("same-key", es, section + ":" + key))
    # Same script trigger under different labels can shadow behavior; compare all.
    triggers = {}
    for e in kept:
        if e.section == "Script":
            triggers.setdefault((e.phase, e.pattern), []).append(e)
    for key, es in triggers.items():
        if len(es) > 1 and len({e.key for e in es}) > 1:
            potential.append(conflict("script-trigger", es, str(key)))
    # Same literal request pattern across response-generation mechanisms needs review.
    patterns = {}
    for e in kept:
        if e.section in {"URL Rewrite", "Map Local", "Script"} and e.phase == "http-request":
            patterns.setdefault(e.pattern, []).append(e)
    for key, es in patterns.items():
        if len({e.section for e in es}) > 1:
            potential.append(conflict("cross-section-request", es, key))
    dropped, used = set(), set()
    for c in potential:
        d = decisions.get(c["id"])
        valid_ids = {e["id"] for e in c["entries"]}
        if d:
            if not set(d["entry_ids"]) <= valid_ids:
                raise Invalid("override contains an entry outside its exact conflict")
            # Keeping multiple script labels/colliding key definitions is not a resolution.
            if len(d["entry_ids"]) != 1:
                raise Invalid("each override must keep exactly one conflicting entry")
            dropped |= valid_ids - set(d["entry_ids"]); used.add(c["id"])
            report["resolved"].append({**c, "decision": d})
        else:
            report["conflicts"].append(c)
    if set(decisions) - used:
        raise Invalid("unused/stale override; review it against current source hashes")
    kept = [e for e in kept if e.id not in dropped]
    # Resolutions must not contradict another resolution by dropping its selected entry.
    for c in report["resolved"]:
        if any(i in dropped for i in c["decision"]["entry_ids"]):
            raise Invalid("contradictory overrides")
    if report["conflicts"]:
        report["status"] = "blocked_conflicts"
        return None, report
    output = ["#!name=Surge 合并候选（需本机验证）", "#!desc=Deterministic candidate; static checks only"]
    for k, v in metadata.items():
        output.append(f"#!{k}={v}")
    # Follow base section ordering, append newly encountered complementary sections.
    order = list(dict.fromkeys(e.section for e in kept))
    for section in order:
        output += ["", f"[{section}]"]
        es = [e for e in kept if e.section == section]
        if section in {"MITM", "General"}:
            for key in dict.fromkeys(e.key for e in es):
                matches = [e for e in es if e.key == key]
                parsed = [host_list(e.raw.partition("=")[2].strip()) for e in matches]
                mode = parsed[0][0]
                hosts = list(dict.fromkeys(h for _, hs in parsed for h in hs))
                output.append(f"{key} = " + (f"%{mode}% " if mode != "replace" else "") + ", ".join(hosts))
        else:
            output.extend(e.raw for e in es)
    text = "\n".join(output) + "\n"
    parse_module(text.encode(), "merged-self-check")
    report.update(status="candidate_static_pass", counts_after=dict(Counter(e.section for e in kept)), sha256=digest(text))
    return text, report
