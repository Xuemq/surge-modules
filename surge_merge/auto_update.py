"""Fail-closed fmz-only updates. Upstream files are data, never executed.

The read-only prepare job validates a candidate. A separate publish job consumes
only a hash-bound, exact-path package and fast-forwards one atomic Git commit.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter, defaultdict
from copy import deepcopy
from datetime import date, datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import urllib.request

from .core import Invalid, clean_bytes, digest, params, parse_module, unquote, words
from .pipeline import MAX_BYTES, NoRedirect, atomic_write, download, json_write, load_manifest, read_json, verify_bytes
from .single import optimize_single

REPOSITORY = "Xuemq/surge-modules"
UPSTREAM = "https://raw.githubusercontent.com/fmz200/wool_scripts/"
SOURCE_PATH = "Surge/module/blockAds.module"
SOURCE_URL = UPSTREAM + "main/" + SOURCE_PATH
UPSTREAM_REF = "https://api.github.com/repos/fmz200/wool_scripts/git/ref/heads/main"
MODULE_PATH = "modules/fmz200.optimized.sgmodule"
LICENSE_PATH = "licenses/fmz200-GPL-3.0.txt"
PUBLIC_FILES = (MODULE_PATH, "sources-fmz.json", "fmz-policy.json", "reports/fmz200-build-report.json", "reports/fmz200-update.json", "NOTICE.md")
PACKAGE_FILES = PUBLIC_FILES + (LICENSE_PATH,)
HEX40 = re.compile(r"[0-9a-f]{40}\Z")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")


class Blocked(Invalid):
    """Only constant, public-safe reason codes cross the logging boundary."""


class PublicationUncertain(Blocked):
    """A final API response was inconclusive; inspect main before any retry."""


def require(value, code):
    if not value:
        raise Blocked(code)


def json_bytes(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode()


def commit_sha(value):
    require(isinstance(value, str) and HEX40.fullmatch(value), "invalid_commit_id")
    return value


def github_json(url, *, method="GET", payload=None, token=None):
    # Call sites construct all URLs; no URL is taken from an API response.
    allowed = url == UPSTREAM_REF or url.startswith(f"https://api.github.com/repos/{REPOSITORY}/git/")
    require(allowed, "unapproved_api_destination")
    headers = {"User-Agent": "surge-fmz-safe-updater/1", "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        require(url.startswith(f"https://api.github.com/repos/{REPOSITORY}/git/"), "token_destination_blocked")
        headers["Authorization"] = "Bearer " + token
    body = json_bytes(payload) if payload is not None else None
    if body is not None:
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        require(response.status in {200, 201} and response.geturl() == url, "unexpected_api_response")
        data = response.read(MAX_BYTES + 1)
    require(len(data) <= MAX_BYTES, "oversized_api_response")
    result = json.loads(data)
    require(isinstance(result, dict), "unexpected_api_shape")
    return result


def source_commit(source):
    match = re.fullmatch(re.escape(UPSTREAM) + r"([0-9a-f]{40})/" + re.escape(SOURCE_PATH), source.get("immutable_url", ""))
    require(match is not None, "source_requires_exact_immutable_url")
    return match[1]


def validate_scope(manifest, policy):
    require(manifest.get("schema_version") == 1 and manifest.get("base") == "fmz200"
            and len(manifest.get("sources", [])) == 1, "fmz_only_manifest_required")
    source = manifest["sources"][0]
    require(source.get("id") == "fmz200" and source.get("format") == "surge"
            and source.get("url") == SOURCE_URL, "fmz_only_source_required")
    source_commit(source)
    require(manifest.get("redistribution", {}).get("approved") is True
            and manifest.get("conversion_policy", {}).get("reviewed") is True, "redistribution_not_approved")
    require(policy.get("schema_version") == 1 and policy.get("source_id") == "fmz200"
            and policy.get("source_sha256") == source.get("sha256"), "policy_lock_mismatch")
    require(isinstance(policy.get("module_metadata"), dict)
            and set(policy["module_metadata"]) == {"name", "desc"}, "reviewed_metadata_required")
    return source


def raw_records(data):
    """Index exact section/hash identities before repairing legacy syntax."""
    records, section = [], None
    for n, line in enumerate(clean_bytes(data).splitlines(), 1):
        raw = line.strip()
        if raw.startswith("[") and raw.endswith("]"):
            section = raw[1:-1]
        elif raw and not raw.startswith(("#", "//", ";")):
            records.append((section, digest(raw), n))
    return records


def migrate_policy(old_data, new_data, policy, modification_date):
    """Move line anchors only when an exact target remains unambiguous.

    No fuzzy matching, app names, domain wildcards, or accepting changed repairs.
    Repeated repair targets must retain their original occurrence count.
    """
    require(digest(old_data) == policy.get("source_sha256"), "old_policy_lock_mismatch")
    # Validate the old policy against its source first, including every anchor.
    optimize_single(old_data, "fmz200", policy)
    old, new = raw_records(old_data), raw_records(new_data)
    migrated = deepcopy(policy)
    for selection in migrated.get("scope_exclusions", []):
        identity = (selection["section"], selection["line_sha256"])
        before = [n for sec, sha, n in old if (sec, sha) == identity]
        after = [n for sec, sha, n in new if (sec, sha) == identity]
        require(before == [selection["line"]] and len(after) == 1, "scope_target_missing_changed_or_ambiguous")
        selection["line"] = after[0]
    for sha in policy.get("script_argument_repairs", {}):
        before = [(sec, h) for sec, h, _ in old if h == sha]
        after = [(sec, h) for sec, h, _ in new if h == sha]
        require(before and all(sec == "Script" for sec, _ in before) and before == after,
                "repair_target_missing_changed_or_ambiguous")
    for decision in policy.get("confirmed_invalid_entries", []):
        sha = decision["line_sha256"]
        before = Counter((sec, h) for sec, h, _ in old if h == sha)
        after = Counter((sec, h) for sec, h, _ in new if h == sha)
        require(before and before == after, "removal_target_missing_changed_or_ambiguous")
    # UTC calendar dates are captured in the lock, making each release replayable.
    date.fromisoformat(modification_date)
    migrated["source_sha256"] = digest(new_data)
    if old_data != new_data:
        migrated["modification_date"] = modification_date
    return migrated


def conflict_signatures(module):
    """Known literal conflicts, including order; never execute regexes or jq."""
    groups, triggers, requests = defaultdict(list), defaultdict(list), defaultdict(list)
    for entry in module.entries:
        groups[(entry.section, entry.key)].append(entry)
        if entry.section == "Script":
            triggers[(entry.phase, entry.pattern)].append(entry)
        if entry.section in {"URL Rewrite", "Map Local", "Script"} and entry.phase == "http-request":
            requests[entry.pattern].append(entry)
    signatures = set()
    for key, entries in groups.items():
        if len({e.id for e in entries}) > 1:
            signatures.add(("same-key", key, tuple(e.id for e in entries)))
    for key, entries in triggers.items():
        if len(entries) > 1:
            signatures.add(("script-trigger", key, tuple(e.id for e in entries)))
    for key, entries in requests.items():
        if len({e.section for e in entries}) > 1:
            signatures.add(("cross-section", key, tuple(e.id for e in entries)))
    return signatures


def retained_conflict_signatures(data, report):
    by_line = {n: (section, sha) for section, sha, n in raw_records(data)}
    return {(item["section"], item["key"], tuple(by_line[n] for n in item["lines"]))
            for item in report["retained_conflicts"]}


def runtime_urls(module):
    result = set()
    for entry in module.entries:
        if entry.section == "Script":
            result.add(params(entry.raw.partition("=")[2])["script-path"])
        elif entry.section == "Map Local":
            fields = dict(token.split("=", 1) for token in words(entry.raw)[1:] if "=" in token)
            if fields.get("data-type", "file") == "file":
                result.add(unquote(fields["data"]))
    return result


def header_directives(data):
    result = []
    for line in clean_bytes(data).splitlines():
        raw = line.strip()
        if raw.startswith("#!"):
            key, sep, value = raw[2:].partition("=")
            require(sep and key, "malformed_upstream_metadata")
            result.append((key, value))
    return result


def validate_delta(old_data, new_data, old_output, new_output):
    old = parse_module(old_output.encode(), "baseline")
    new = parse_module(new_output.encode(), "candidate")
    require(old.metadata == new.metadata, "semantic_metadata_changed")
    old_directives, new_directives = header_directives(old_data), header_directives(new_data)
    require(Counter(k for k, _ in new_directives) == Counter(k for k, _ in old_directives),
            "upstream_directive_set_changed")
    # Attribution is retained; losing it needs a human review, even if parseable.
    require([v for k, v in old_directives if k == "author"] == [v for k, v in new_directives if k == "author"],
            "upstream_attribution_changed")
    protected = lambda m: [(e.section, e.raw) for e in m.entries if e.section in {"MITM", "General"}]
    require(protected(old) == protected(new), "mitm_or_general_changed")
    require(runtime_urls(new) <= runtime_urls(old), "new_runtime_dependency_requires_review")
    old_scripts = Counter(e.id for e in old.entries if e.section == "Script")
    new_scripts = Counter(e.id for e in new.entries if e.section == "Script")
    require(new_scripts <= old_scripts, "script_definition_changed_requires_review")
    # Redirect/header rewriting can transmit requests or credentials elsewhere.
    # A parser accepting the syntax is not permission to change routing.
    nonreject = lambda e: e.section == "URL Rewrite" and not (len(words(e.raw)) == 3 and words(e.raw)[2] == "reject")
    old_redirects = Counter(e.id for e in old.entries if nonreject(e))
    new_redirects = Counter(e.id for e in new.entries if nonreject(e))
    require(new_redirects <= old_redirects, "redirect_definition_changed_requires_review")
    old_headers = Counter(e.id for e in old.entries if e.section == "Header Rewrite")
    new_headers = Counter(e.id for e in new.entries if e.section == "Header Rewrite")
    require(new_headers <= old_headers, "header_definition_changed_requires_review")
    require(conflict_signatures(new) <= conflict_signatures(old), "new_or_changed_literal_conflict")
    old_ids, new_ids = [e.id for e in old.entries], [e.id for e in new.entries]
    shared = set(old_ids) & set(new_ids)
    # Keep every retained occurrence. Sequential A,B,A -> A,A,B is a behavior
    # change even though its unique-ID order is identical. A changed duplicate
    # count for a retained rule is ambiguous and also requires review.
    common_order = lambda ids: [i for i in ids if i in shared]
    require(common_order(old_ids) == common_order(new_ids), "existing_rule_order_changed")
    removed = sum((Counter(old_ids) - Counter(new_ids)).values())
    added = sum((Counter(new_ids) - Counter(old_ids)).values())
    require(max(added, removed) <= max(25, len(old_ids) // 10), "large_rule_delta_requires_review")
    return {"added_active_entries": added, "removed_active_entries": removed,
            "inherited_literal_conflict_groups": len(conflict_signatures(new))}


def make_notice(manifest, policy, report):
    source = manifest["sources"][0]
    changes = report["changes_by_kind"]
    exclusions = len(policy.get("scope_exclusions", []))
    return f'''# fmz200 单来源优化说明

此模块仅派生于 fmz200/wool_scripts，不含 blackmatrix7 或墨鱼规则合并。
上游作者：fmz200（奶思）及原文件中注明的贡献者；模块内保留原作者信息。
上游固定版本：{source['immutable_url']}
原文件 SHA-256：{source['sha256']}
本次修改日期：{policy['modification_date']}
修改者：Xuemq（通过本仓库原创优化工具）
模块 SHA-256：{report['output_sha256']}

许可：沿用上游 GNU GPL v3；完整许可见 licenses/fmz200-GPL-3.0.txt。
修改：安全完全重复项去重 {changes.get('exact-duplicate', 0)} 条；重复脚本标签确定性改名 {changes.get('unique-script-label', 0)} 项；具名 JSON 参数修复 {changes.get('script-argument-object', 0)} 行；JSON 等值 base64 修复 {changes.get('json-map-base64', 0)} 行；恢复有证据的缺失参数默认值；保留原有不同操作与顺序。
明确选择的范围排除：{exclusions} 条，均绑定原始段名和行哈希，不代表它们已经失效。自动更新仅允许精确目标移动行号，不能扩大删除范围或自动改写决定。完整逐行报告见 reports/fmz200-build-report.json；首次范围精简的历史对比见 reports/fmz200-scope-diff.json（不代表后续版本差异）。

每日安全更新与手动运行通过后，发布至同一个 modules/fmz200.optimized.sgmodule 地址。任何校验、下载、测试或发布门禁失败时保留最后成功版本。自动发布记录见 reports/fmz200-update.json；复现使用 sources-fmz.json 和 fmz-policy.json。

引用脚本和资源仍使用上游 URL，不打包或执行其正文。相同 URL 的远端内容仍可能独立变化；模块可复现不保证远端依赖不变。不会仅凭超时、403、年龄或域名猜测删除规则。
仅完成静态检查与合成测试，尚未在 Surge iOS 实机运行，也没有正则匹配集合重叠或广告有效性证明。jq Body Rewrite 要求 Surge iOS 5.14+；远程脚本可能有更高要求。详细门禁和限制见 docs/auto-updates.md。
'''.encode()


def build_release(root, old_data, new_data, new_commit, new_license, modification_date):
    """Pure candidate generation; never writes tracked files or changes main."""
    root = Path(root)
    manifest, policy = load_manifest(root / "sources-fmz.json"), read_json(root / "fmz-policy.json")
    source = validate_scope(manifest, policy)
    commit_sha(new_commit)
    verify_bytes(source, old_data)
    clean_bytes(new_data)
    require(new_license == (root / LICENSE_PATH).read_bytes(), "upstream_license_changed")
    old_output, old_report = optimize_single(old_data, "fmz200", policy)
    require(old_output.encode() == (root / MODULE_PATH).read_bytes(), "published_baseline_not_reproducible")
    migrated = migrate_policy(old_data, new_data, policy, modification_date)
    new_output, report = optimize_single(new_data, "fmz200", migrated)
    require(retained_conflict_signatures(new_data, report) <= retained_conflict_signatures(old_data, old_report),
            "new_or_changed_inherited_conflict")
    delta = validate_delta(old_data, new_data, old_output, new_output)
    updated = deepcopy(manifest)
    if new_data != old_data:
        s = updated["sources"][0]
        s.update(sha256=digest(new_data), bytes=len(new_data), immutable_url=UPSTREAM + new_commit + "/" + SOURCE_PATH)
        updated["redistribution"]["license_url"] = "https://github.com/fmz200/wool_scripts/blob/" + new_commit + "/LICENSE"
    record = {"schema_version": 1, "scope": "fmz200-only", "static_only": True,
              "source_sha256": digest(new_data), "source_commit": source_commit(updated["sources"][0]),
              "module_sha256": report["output_sha256"], "license_sha256": digest(new_license),
              "scope_exclusion_count": len(migrated.get("scope_exclusions", [])),
              "policy_sha256": digest(json_bytes(migrated)),
              "modification_date": migrated["modification_date"]}
    files = {MODULE_PATH: new_output.encode(), "sources-fmz.json": json_bytes(updated),
             "fmz-policy.json": json_bytes(migrated), "reports/fmz200-build-report.json": json_bytes(report),
             "reports/fmz200-update.json": json_bytes(record), "NOTICE.md": make_notice(updated, migrated, report),
             LICENSE_PATH: new_license}
    require(set(files) == set(PACKAGE_FILES), "unexpected_release_path")
    changed_paths = [path for path in PUBLIC_FILES if not (root / path).exists() or (root / path).read_bytes() != files[path]]
    status = {"schema_version": 1, "status": "ready" if changed_paths else "unchanged",
              "source_changed": new_data != old_data, "observed_upstream_commit": new_commit,
              "source_sha256": digest(new_data), "module_sha256": report["output_sha256"],
              "scope_exclusions": record["scope_exclusion_count"], "changed_paths": changed_paths, **delta}
    return files, status


def write_package(folder, files, base_sha):
    folder = Path(folder)
    commit_sha(base_sha)
    require(not folder.exists(), "package_destination_must_be_new")
    require(set(files) == set(PACKAGE_FILES), "unexpected_release_path")
    # The manifest is written last. A partial folder can never pass verification.
    package = {"schema_version": 1, "repository": REPOSITORY, "base_sha": base_sha,
               "files": {path: {"sha256": digest(data), "bytes": len(data)} for path, data in files.items()}}
    for path, data in files.items():
        atomic_write(folder / path, data)
    encoded = json_bytes(package)
    atomic_write(folder / "package.json", encoded)
    return digest(encoded)


def verify_package(folder, expected_digest, base_sha):
    folder = Path(folder)
    require(isinstance(expected_digest, str) and HEX64.fullmatch(expected_digest), "invalid_package_digest")
    commit_sha(base_sha)
    require(folder.is_dir() and not folder.is_symlink(), "invalid_package_directory")
    files_on_disk = set()
    for path in folder.rglob("*"):
        require(not path.is_symlink(), "package_symlink_forbidden")
        if path.is_file():
            files_on_disk.add(path.relative_to(folder).as_posix())
        else:
            require(path.is_dir(), "package_nonregular_file")
    require(files_on_disk == set(PACKAGE_FILES) | {"package.json"}, "unexpected_package_path")
    require((folder / "package.json").stat().st_size < 16384, "oversized_package_manifest")
    encoded = (folder / "package.json").read_bytes()
    require(digest(encoded) == expected_digest, "package_digest_mismatch")
    package = json.loads(encoded)
    require(set(package) == {"schema_version", "repository", "base_sha", "files"}
            and package["schema_version"] == 1 and package["repository"] == REPOSITORY
            and package["base_sha"] == base_sha and set(package["files"]) == set(PACKAGE_FILES), "package_binding_mismatch")
    result = {}
    for path in PACKAGE_FILES:
        require(0 < (folder / path).stat().st_size <= MAX_BYTES, "invalid_package_file_size")
        data = (folder / path).read_bytes()
        require(package["files"][path] == {"sha256": digest(data), "bytes": len(data)}, "package_file_hash_mismatch")
        clean_bytes(data)
        result[path] = data
    record = json.loads(result["reports/fmz200-update.json"])
    require(record["module_sha256"] == digest(result[MODULE_PATH])
            and record["policy_sha256"] == digest(result["fmz-policy.json"])
            and record["license_sha256"] == digest(result[LICENSE_PATH]), "release_record_mismatch")
    parse_module(result[MODULE_PATH], "package-self-check")
    return result


def prepare(root, folder, base_sha, modification_date=None):
    root = Path(root)
    manifest, policy = load_manifest(root / "sources-fmz.json"), read_json(root / "fmz-policy.json")
    source = validate_scope(manifest, policy)
    old = download(source["immutable_url"])
    verify_bytes(source, old)
    ref = github_json(UPSTREAM_REF)
    require(ref.get("ref") == "refs/heads/main" and ref.get("object", {}).get("type") == "commit", "invalid_upstream_ref")
    sha = commit_sha(ref["object"]["sha"])
    new = download(UPSTREAM + sha + "/" + SOURCE_PATH)
    license_data = download(UPSTREAM + sha + "/LICENSE")
    day = modification_date or datetime.now(timezone.utc).date().isoformat()
    files, status = build_release(root, old, new, sha, license_data, day)
    if status["status"] == "ready":
        status["package_sha256"] = write_package(folder, files, base_sha)
        verify_package(folder, status["package_sha256"], base_sha)
    return status


def publish(folder, expected_digest, base_sha, token):
    """Atomic fast-forward only; no PAT, force push, retries, or other repo writes."""
    require(os.environ.get("GITHUB_REPOSITORY") == REPOSITORY
            and os.environ.get("GITHUB_REF") == "refs/heads/main"
            and os.environ.get("GITHUB_EVENT_NAME") in {"schedule", "workflow_dispatch", "push"}, "publish_requires_approved_workflow_context")
    require(isinstance(token, str) and token, "missing_builtin_workflow_token")
    files = verify_package(folder, expected_digest, base_sha)
    api = f"https://api.github.com/repos/{REPOSITORY}/git/"
    request = lambda suffix, **kwargs: github_json(api + suffix, token=token, **kwargs)
    current = request("ref/heads/main")
    require(current.get("object", {}).get("sha") == base_sha, "main_advanced_rebuild_required")
    base = request("commits/" + base_sha)
    base_tree = commit_sha(base["tree"]["sha"])
    tree_entries = []
    for path in PUBLIC_FILES:
        blob = request("blobs", method="POST", payload={"content": base64.b64encode(files[path]).decode(), "encoding": "base64"})
        tree_entries.append({"path": path, "mode": "100644", "type": "blob", "sha": commit_sha(blob["sha"])})
    tree = request("trees", method="POST", payload={"base_tree": base_tree, "tree": tree_entries})
    tree_sha = commit_sha(tree["sha"])
    if tree_sha == base_tree:
        return {"schema_version": 1, "status": "unchanged", "commit": base_sha}
    record = json.loads(files["reports/fmz200-update.json"])
    commit = request("commits", method="POST", payload={"message": "chore: safely refresh fmz200 module " + record["source_sha256"][:12],
                     "tree": tree_sha, "parents": [base_sha]})
    sha = commit_sha(commit["sha"])
    # force:false rejects races. An uncertain response is never blindly retried.
    try:
        request("refs/heads/main", method="PATCH", payload={"sha": sha, "force": False})
        verified = request("ref/heads/main")
        require(verified.get("object", {}).get("sha") == sha, "publication_not_confirmed_check_main")
    except Exception as exc:
        # No blind retry: an interrupted PATCH can already have succeeded.
        raise PublicationUncertain("publication_unconfirmed_check_main") from exc
    return {"schema_version": 1, "status": "published", "commit": sha, "module_sha256": record["module_sha256"]}


def emit_status(status):
    # All values below are generated codes, counts, fixed paths or validated hashes.
    print(status["status"])
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as handle:
            handle.write("### fmz200 safe update\n\nStatus: " + status["status"] + "\n\n")
            for key in ("reason", "source_sha256", "module_sha256", "scope_exclusions", "commit"):
                if key in status:
                    handle.write(f"- {key}: {status[key]}\n")
            handle.write("\nStatic checks only. Validation failures publish nothing. If publication is unconfirmed, inspect main before retrying.\n")
    output = os.environ.get("GITHUB_OUTPUT")
    if output:
        with open(output, "a", encoding="utf-8") as handle:
            handle.write("changed=" + str(status["status"] == "ready").lower() + "\n")
            if "package_sha256" in status:
                handle.write("package_sha256=" + status["package_sha256"] + "\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare", "verify-package", "publish"))
    parser.add_argument("--root", default=".")
    parser.add_argument("--package", default="work/fmz-auto-package")
    parser.add_argument("--base-sha", default=os.environ.get("GITHUB_SHA", ""))
    parser.add_argument("--package-sha256", default=os.environ.get("EXPECTED_PACKAGE_SHA256", ""))
    parser.add_argument("--report", default="work/fmz-auto-status.json")
    args = parser.parse_args(argv)
    try:
        commit_sha(args.base_sha)
        if args.command == "prepare":
            status = prepare(args.root, args.package, args.base_sha)
        elif args.command == "verify-package":
            verify_package(args.package, args.package_sha256, args.base_sha)
            status = {"schema_version": 1, "status": "package_verified"}
        else:
            status = publish(args.package, args.package_sha256, args.base_sha, os.environ.get("GITHUB_TOKEN"))
        result = 0
    except Exception as exc:
        # Remote bodies, exception text, URLs, credentials and source snippets are
        # never emitted to public logs, output files, summaries or Actions commands.
        reason = str(exc) if isinstance(exc, Blocked) and re.fullmatch(r"[a-z_]+", str(exc)) else "fetch_or_validation_failed"
        status = {"schema_version": 1, "status": "publication_unconfirmed" if isinstance(exc, PublicationUncertain) else "blocked", "reason": reason}
        result = 2
    json_write(args.report, status)
    emit_status(status)
    return result


if __name__ == "__main__":
    raise SystemExit(main())
