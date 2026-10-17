"""Independent, conservative QX rewrite conversion. Never executes source scripts."""
from collections import Counter
import re
from .core import Invalid, clean_bytes, digest, parse_module


def quote(value):
    if "'" in value or "\n" in value or "\r" in value:
        raise Invalid("cannot preserve quoting safely")
    return "'" + value + "'"


def convert_qx(data: bytes, policy=None):
    policy = policy or {"approved_script_urls": [], "approved_request_body_hashes": []}
    text = clean_bytes(data)
    sections = {}
    report = {"schema_version": 1, "source_sha256": digest(data), "directives": {}, "unsupported": [], "converted": 0, "static_only": True, "warnings": []}
    counts = Counter()
    for n, line in enumerate(text.splitlines(), 1):
        raw = line.strip()
        if not raw or raw.startswith(("#", "//", ";")):
            continue
        kind = "unknown"
        try:
            if raw.startswith("hostname"):
                kind = "hostname"
                key, eq, hosts = raw.partition("=")
                if key.strip() != "hostname" or not eq:
                    raise Invalid("malformed hostname directive")
                section, native = "MITM", "hostname = %APPEND% " + hosts.strip()
            elif re.match(r"^(?:host|host-suffix|host-keyword|ip-cidr|ip6-cidr)\s*,", raw):
                kind = "routing-rule"
                fields = [s.strip() for s in raw.split(",")]
                names = {"host": "DOMAIN", "host-suffix": "DOMAIN-SUFFIX", "host-keyword": "DOMAIN-KEYWORD", "ip-cidr": "IP-CIDR", "ip6-cidr": "IP-CIDR6"}
                if len(fields) != 3 or fields[2].lower() not in {"direct", "reject", "reject-tinygif"}:
                    raise Invalid("unsupported QX routing rule")
                section, native = "Rule", f"{names[fields[0]]},{fields[1]},{fields[2].upper()}"
            else:
                parts = re.split(r"\s+url\s+", raw, maxsplit=1)
                if len(parts) != 2 or not parts[0]:
                    raise Invalid("unsupported QX line")
                pattern, action = parts
                kind, _, value = action.partition(" ")
                value = value.strip()
                if kind == "reject" and not value:
                    section, native = "URL Rewrite", pattern + " _ reject"
                elif kind in {"reject-200", "reject-dict", "reject-array", "reject-img"} and not value:
                    bodies = {"reject-200": 'data-type=text data=" " status-code=200', "reject-dict": 'data-type=text data="{}" status-code=200 header="Content-Type:application/json"', "reject-array": 'data-type=text data="[]" status-code=200 header="Content-Type:application/json"', "reject-img": 'data-type=tiny-gif status-code=200'}
                    section, native = "Map Local", pattern + " " + bodies[kind]
                elif kind in {"response-body", "request-body"}:
                    if kind == "request-body" and digest(raw) not in policy.get("approved_request_body_hashes", []):
                        raise Invalid("request-body behavior needs explicit line-hash review; may be unrelated to ads")
                    pair = value.split(" " + kind + " ")
                    if len(pair) != 2 or not all(pair):
                        raise Invalid("unsupported body replacement structure")
                    phase = "http-response" if kind == "response-body" else "http-request"
                    section, native = "Body Rewrite", f"{phase} {pattern} {quote(pair[0])} {quote(pair[1])}"
                elif kind in {"jsonjq-response-body", "jsonjq-request-body"}:
                    if not value or value[0] != "'" or value[-1] != "'":
                        raise Invalid("jq expression must have explicit single quotes")
                    phase = "http-response-jq" if kind == "jsonjq-response-body" else "http-request-jq"
                    section, native = "Body Rewrite", f"{phase} {pattern} {value}"
                elif kind == "echo-response":
                    pair = value.split(" echo-response ")
                    if len(pair) != 2 or pair[1] not in policy.get("approved_static_response_urls", []):
                        raise Invalid("static response URL/content type has not been reviewed")
                    mime, url = pair
                    if not re.fullmatch(r"[a-zA-Z0-9.+-]+/[a-zA-Z0-9.+-]+", mime):
                        raise Invalid("unsupported echo-response content type")
                    section, native = "Map Local", f'{pattern} data-type=file data="{url}" status-code=200 header="Content-Type:{mime}"'
                elif kind == "script-analyze-echo-response":
                    if value not in policy.get("approved_analyze_script_urls", []):
                        raise Invalid("analyze-echo script must explicitly support Surge request short-circuiting")
                    label = "moyu_" + digest(raw)[:16]
                    section, native = "Script", f"{label} = type=http-request, pattern={quote(pattern)}, script-path={value}, requires-body=true"
                elif kind in {"script-response-body", "script-response-header", "script-request-body", "script-request-header"}:
                    incompatible = next((item for item in policy.get("known_incompatible", []) if item.get("url") == value), None)
                    if incompatible:
                        raise Invalid("reviewed script has no equivalent Surge effect: " + incompatible["reason"])
                    if value not in policy.get("approved_script_urls", []):
                        raise Invalid("external script runtime compatibility has not been reviewed")
                    phase = "http-response" if "response" in kind else "http-request"
                    label = "moyu_" + digest(raw)[:16]
                    section, native = "Script", f"{label} = type={phase}, pattern={quote(pattern)}, script-path={value}, requires-body={'true' if kind.endswith('-body') else 'false'}"
                    if value in policy.get("binary_script_urls", []):
                        native += ", binary-body-mode=true"
                else:
                    raise Invalid("unsupported conversion; no equivalent behavior has been verified")
            sections.setdefault(section, []).append(native)
            report["converted"] += 1
        except Invalid as exc:
            report["unsupported"].append({"line": n, "directive": kind, "line_sha256": digest(raw), "reason": str(exc)})
        counts[kind] += 1
    report["directives"] = dict(counts)
    if not counts:
        raise Invalid("no active QX directives")
    if report["unsupported"]:
        report["status"] = "blocked_conversion"
        return None, report
    out = ["#!name=墨鱼转换候选", "#!desc=Independent conversion; runtime validation required", "#!system=ios"]
    for section, entries in sections.items():
        out.extend(["", f"[{section}]", *entries])
    candidate = "\n".join(out) + "\n"
    parse_module(candidate.encode(), "moyu-converted")
    report.update(status="converted_static_pass", output_sha256=digest(candidate))
    return candidate, report
