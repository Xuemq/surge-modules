"""Synthetic updates exercise the full preparation/publication boundary offline."""
from copy import deepcopy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from surge_merge import auto_update as auto
from surge_merge.core import digest
from surge_merge.pipeline import json_write
from surge_merge.single import optimize_single


OLD_SHA = "1" * 40
NEW_SHA = "2" * 40
BASE_SHA = "3" * 40
LICENSE = b"Reviewed license fixture\n"
RULE = "DOMAIN,excluded.example,REJECT"
SCRIPT = "repair = type=http-response, pattern=^repair, script-path=https://example.test/repair.js, argument=[{flag}]"
OLD = ("#!name=Original\n#!desc=Upstream\n#!author=Original author\n"
       "[Rule]\n" + RULE + "\nDOMAIN,keep.example,REJECT\n"
       "[Script]\n" + SCRIPT + "\n[MITM]\nhostname = %APPEND% keep.example\n").encode()


def fixture_policy(data=OLD):
    return {"schema_version": 1, "source_id": "fmz200", "source_sha256": digest(data),
            "modification_date": "2026-10-17", "argument_defaults": {"flag": "true"},
            "script_argument_repairs": {digest(SCRIPT): {"argument": '\"{\"flag\":{{{flag}}}}\"', "reason": "Reviewed shape", "evidence": "https://example.test/original"}},
            "confirmed_invalid_entries": [], "scope_exclusions": [{"line": 5, "section": "Rule", "line_sha256": digest(RULE),
            "classification": "manual-scope-exclusion", "reason": "Exact reviewed choice."}],
            "module_metadata": {"name": "去广告优化 · fmz200", "desc": "Static-only optimized module."}}


class AutoUpdateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "repo"
        self.root.mkdir()
        self.policy = fixture_policy()
        self.manifest = {"schema_version": 1, "base": "fmz200", "sources": [{"id": "fmz200", "format": "surge", "url": auto.SOURCE_URL,
                         "immutable_url": auto.UPSTREAM + OLD_SHA + "/" + auto.SOURCE_PATH, "sha256": digest(OLD), "bytes": len(OLD)}],
                         "redistribution": {"approved": True}, "conversion_policy": {"reviewed": True}}
        json_write(self.root / "sources-fmz.json", self.manifest)
        json_write(self.root / "fmz-policy.json", self.policy)
        self.install(auto.MODULE_PATH, optimize_single(OLD, "fmz200", self.policy)[0].encode())
        self.install(auto.LICENSE_PATH, LICENSE)
        self.package = Path(self.tmp.name) / "package"

    def tearDown(self):
        self.tmp.cleanup()

    def install(self, path, data):
        dest = self.root / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(data)

    def build(self, data=OLD, **kwargs):
        return auto.build_release(self.root, OLD, data, kwargs.get("commit", NEW_SHA), kwargs.get("license", LICENSE), "2026-10-18")

    def assertBlocked(self, data, code=None, **kwargs):
        before = {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        with self.assertRaises(auto.Invalid) as caught:
            self.build(data, **kwargs)
        if code:
            self.assertEqual(str(caught.exception), code)
        self.assertEqual(before, {p.relative_to(self.root): p.read_bytes() for p in self.root.rglob("*") if p.is_file()})

    def package_ready(self, data=OLD):
        files, status = self.build(data)
        sha = auto.write_package(self.package, files, BASE_SHA)
        return files, sha

    def test_initial_run_prepares_real_publication_without_module_change(self):
        files, status = self.build()
        self.assertEqual(status["status"], "ready")
        self.assertFalse(status["source_changed"])
        self.assertEqual(files[auto.MODULE_PATH], (self.root / auto.MODULE_PATH).read_bytes())
        self.assertNotIn(auto.MODULE_PATH, status["changed_paths"])
        self.assertEqual(set(files), set(auto.PACKAGE_FILES))

    def test_normal_unchanged_run_does_not_commit_or_change_date(self):
        files, _ = self.build()
        for path, data in files.items():
            self.install(path, data)
        again, status = self.build()
        self.assertEqual(status["status"], "unchanged")
        self.assertEqual(again, files)
        self.assertEqual(json.loads(again["fmz-policy.json"])["modification_date"], "2026-10-17")

    def test_safe_changed_source_migrates_exclusion_and_lock(self):
        new = b"# added upstream comment\n" + OLD.replace(b"[Script]", b"[URL Rewrite]\n^https://new.example/ _ reject\n[Script]")
        files, status = self.build(new)
        policy = json.loads(files["fmz-policy.json"])
        self.assertEqual(policy["scope_exclusions"][0]["line"], 6)
        expected = deepcopy(self.policy["scope_exclusions"][0]); expected["line"] = 6
        self.assertEqual(policy["scope_exclusions"], [expected])
        self.assertNotIn(RULE.encode(), files[auto.MODULE_PATH])
        self.assertIn(b"^https://new.example/ _ reject", files[auto.MODULE_PATH])
        self.assertEqual(policy["module_metadata"], self.policy["module_metadata"])
        self.assertEqual(policy["script_argument_repairs"], self.policy["script_argument_repairs"])
        self.assertEqual(status["added_active_entries"], 1)
        self.assertEqual(json.loads(files["sources-fmz.json"])["sources"][0]["sha256"], digest(new))
        self.assertEqual(self.build(new)[0], files)

    def test_target_drift_missing_changed_duplicate_or_section_move_blocks(self):
        variants = (OLD.replace((RULE+"\n").encode(), b""), OLD.replace(b"excluded.example", b"changed.example"),
                    OLD.replace(RULE.encode(), (RULE+"\n"+RULE).encode()), OLD.replace(b"[Rule]", b"[URL Rewrite]"))
        for data in variants:
            with self.subTest(data=data):
                self.assertBlocked(data, "scope_target_missing_changed_or_ambiguous")

    def test_repair_changed_removed_or_duplicated_blocks(self):
        for data in (OLD.replace(SCRIPT.encode(), SCRIPT.replace("^repair", "^changed").encode()),
                     OLD.replace((SCRIPT+"\n").encode(), b""), OLD.replace(SCRIPT.encode(), (SCRIPT+"\n"+SCRIPT).encode())):
            with self.subTest(data=data):
                self.assertBlocked(data, "repair_target_missing_changed_or_ambiguous")

    def test_existing_duplicate_repair_targets_can_move_but_not_multiply(self):
        before = OLD.replace(SCRIPT.encode(), (SCRIPT+"\n"+SCRIPT).encode())
        policy = fixture_policy(before)
        migrated = auto.migrate_policy(before, b"# moved\n"+before, policy, "2026-10-18")
        self.assertEqual(migrated["script_argument_repairs"], policy["script_argument_repairs"])
        with self.assertRaisesRegex(auto.Blocked, "repair_target"):
            auto.migrate_policy(before, before.replace(SCRIPT.encode(), (SCRIPT+"\n"+SCRIPT).encode()), policy, "2026-10-18")

    def test_source_sha_lock_cannot_be_bypassed(self):
        self.policy["source_sha256"] = "f"*64
        json_write(self.root/"fmz-policy.json", self.policy)
        self.assertBlocked(OLD, "policy_lock_mismatch")

    def test_unchanged_source_needs_reproducible_published_baseline(self):
        self.install(auto.MODULE_PATH, b"last-good-but-unreviewed\n")
        self.assertBlocked(OLD, "published_baseline_not_reproducible")

    def test_license_changes_block(self):
        self.assertBlocked(OLD, "upstream_license_changed", license=b"different license\n")

    def test_new_same_key_conflict_blocks(self):
        self.assertBlocked(OLD.replace(b"[Script]", b"DOMAIN,keep.example,DIRECT\n[Script]"), "new_or_changed_inherited_conflict")

    def test_cross_section_and_script_trigger_conflicts_detected(self):
        cases = [b"[URL Rewrite]\n^same _ reject\n[Map Local]\n^same data-type=text data=ok\n",
                 b"[Script]\na = type=http-response, pattern=^same, script-path=https://example.test/a.js\nb = type=http-response, pattern=^same, script-path=https://example.test/a.js\n"]
        for raw in cases:
            self.assertTrue(auto.conflict_signatures(auto.parse_module(raw, "fixture")))

    def test_existing_conflict_keeps_exact_order_and_bodies(self):
        before = b"[Rule]\nDOMAIN,a,REJECT\nDOMAIN,a,DIRECT\n"
        old = auto.parse_module(before, "old")
        moved = auto.parse_module(b"# moved\n"+before, "new")
        reordered = auto.parse_module(b"[Rule]\nDOMAIN,a,DIRECT\nDOMAIN,a,REJECT\n", "new")
        self.assertEqual(auto.conflict_signatures(old), auto.conflict_signatures(moved))
        self.assertNotEqual(auto.conflict_signatures(old), auto.conflict_signatures(reordered))

    def test_mitm_general_and_semantic_metadata_changes_block(self):
        self.assertBlocked(OLD.replace(b"hostname = %APPEND% keep.example", b"hostname = %APPEND% keep.example, *.new.example"), "mitm_or_general_changed")
        self.assertBlocked(OLD+b"[General]\nforce-http-engine-hosts = %APPEND% new.example\n", "mitm_or_general_changed")
        self.assertBlocked(b"#!arguments=flag:false\n"+OLD, "semantic_metadata_changed")

    def test_new_runtime_dependency_blocked(self):
        new = OLD.replace(b"[MITM]", b"new = type=http-response, pattern=^new, script-path=https://evil.example/new.js\n[MITM]")
        self.assertBlocked(new, "new_runtime_dependency_requires_review")
        self.assertBlocked(OLD+b"[Map Local]\n^new data=https://evil.example/response.json\n", "new_runtime_dependency_requires_review")

    def test_map_local_redirect_headers_and_body_changes_require_review(self):
        old='[Rule]\nDOMAIN,keep.test,REJECT\n'
        for status,header in (('302','Location:https://destination.test/'),('307','Location:https://destination.test/'),
                ('200','Refresh:0;url=https://destination.test/'),('200','Set-Cookie:session=fixture')):
            new=old+'[Map Local]\n^https://new.test/ data-type=text data="{}" status-code='+status+' header="'+header+'"\n'
            with self.subTest(status=status,header=header),self.assertRaisesRegex(auto.Blocked,'map_local_definition_changed_requires_review'):
                auto.validate_delta(old.encode(),new.encode(),old,new)
        old+='[Map Local]\n^https://old.test/ data-type=text data="{}"\n'
        for new in (old.replace('data="{}"','data="[]"'),old.replace('^https://old.test/','.*')):
            with self.assertRaisesRegex(auto.Blocked,'map_local_definition_changed_requires_review'):
                auto.validate_delta(old.encode(),new.encode(),old,new)

    def test_exact_reviewed_map_local_can_remain_or_be_removed(self):
        old='[Rule]\nDOMAIN,keep.test,REJECT\n[Map Local]\n^https://old.test/ data-type=text data="{}" status-code=302 header="Location:https://destination.test/"\n'
        for new in (old,'[Rule]\nDOMAIN,keep.test,REJECT\n'):
            result=auto.validate_delta(old.encode(),new.encode(),old,new)
            self.assertEqual(result['added_active_entries'],0)

    def test_new_direct_or_reject_routing_requires_review(self):
        for policy in ('DIRECT','REJECT'):
            new=OLD.replace(b'[Script]',('DOMAIN,auth.example,'+policy+'\n[Script]').encode())
            with self.subTest(policy=policy):self.assertBlocked(new,'routing_definition_changed_requires_review')

    def test_body_rewrite_added_or_changed_requires_review(self):
        old='[Rule]\nDOMAIN,keep.test,REJECT\n'
        for body in ('http-request ^https://new.test/ a b','http-response-jq ^https://new.test/ \'del(.ads)\''):
            new=old+'[Body Rewrite]\n'+body+'\n'
            with self.subTest(body=body),self.assertRaisesRegex(auto.Blocked,'body_definition_changed_requires_review'):
                auto.validate_delta(old.encode(),new.encode(),old,new)
        old+='[Body Rewrite]\nhttp-response ^https://old.test/ a b\n';new=old.replace(' a b',' a c')
        with self.assertRaisesRegex(auto.Blocked,'body_definition_changed_requires_review'):
            auto.validate_delta(old.encode(),new.encode(),old,new)

    def test_runtime_file_url_discovery_handles_quotes(self):
        m = auto.parse_module(b'[Map Local]\n^new data-type=file data="https://example.test/x.json" header="Content-Type:application/json"\n', "fixture")
        self.assertEqual(auto.runtime_urls(m), {"https://example.test/x.json"})

    def test_existing_active_rule_reorder_blocks(self):
        old = "[Rule]\nDOMAIN,a,REJECT\nDOMAIN,b,REJECT\n"
        with self.assertRaisesRegex(auto.Blocked, "existing_rule_order_changed"):
            auto.validate_delta(old.encode(), old.encode(), old, "[Rule]\nDOMAIN,b,REJECT\nDOMAIN,a,REJECT\n")

    def test_sequential_duplicate_occurrence_order_cannot_change(self):
        a = r"http-response ^https://example\.com/ a aa"
        b = r"http-response ^https://example\.com/path aa b"
        old = "[Body Rewrite]\n"+a+"\n"+b+"\n"+a+"\n"
        new = "[Body Rewrite]\n"+a+"\n"+a+"\n"+b+"\n"
        with self.assertRaisesRegex(auto.Blocked,"existing_rule_order_changed"):
            auto.validate_delta(old.encode(),new.encode(),old,new)

    def test_changed_sequential_duplicate_count_requires_review(self):
        a = "http-response ^a a aa"
        old = "[Body Rewrite]\n"+a+"\n"+a+"\n"
        new = "[Body Rewrite]\n"+a+"\n"
        with self.assertRaisesRegex(auto.Blocked,"existing_rule_order_changed"):
            auto.validate_delta(old.encode(),new.encode(),old,new)

    def test_same_url_script_matcher_body_argument_phase_changes_block(self):
        script = "original = type=http-response, pattern=^https://example.test/ads, script-path=https://example.test/same.js, requires-body=false, argument=old"
        old = "[Script]\n"+script+"\n"
        variants = [script.replace("pattern=^https://example.test/ads","pattern=.*"),
                    script.replace("requires-body=false","requires-body=true"),
                    script.replace("argument=old","argument=changed"),
                    script.replace("type=http-response","type=http-request"),
                    script+", max-size=9999999"]
        for changed in variants:
            new = "[Script]\n"+changed+"\n"
            with self.subTest(changed=changed), self.assertRaisesRegex(auto.Blocked,"script_definition_changed_requires_review"):
                auto.validate_delta(old.encode(),new.encode(),old,new)

    def test_new_script_using_existing_url_also_requires_review(self):
        old = "[Script]\na = type=http-response, pattern=^a, script-path=https://example.test/same.js\n"
        new = old+"b = type=http-response, pattern=.*, script-path=https://example.test/same.js\n"
        with self.assertRaisesRegex(auto.Blocked,"script_definition_changed_requires_review"):
            auto.validate_delta(old.encode(),new.encode(),old,new)

    def test_changed_or_added_redirect_destinations_require_review(self):
        old = "[URL Rewrite]\n^https://source.example/path https://old.example/target 302\n"
        variants = [old.replace("old.example", "new.example"),
                    old+"^https://new.example/ https://old.example/target 307\n",
                    old+"^https://source.example/ https://new.example/ header\n"]
        for new in variants:
            with self.subTest(new=new), self.assertRaisesRegex(auto.Blocked,"redirect_definition_changed_requires_review"):
                auto.validate_delta(old.encode(),new.encode(),old,new)

    def test_added_or_changed_header_rewrites_require_review(self):
        old = "[Header Rewrite]\nhttp-request ^a header-del Cookie\n"
        for new in (old.replace("Cookie","Authorization"), old+"http-request ^b header-add Host attacker.example\n"):
            with self.subTest(new=new), self.assertRaisesRegex(auto.Blocked,"header_definition_changed_requires_review"):
                auto.validate_delta(old.encode(),new.encode(),old,new)

    def test_new_reject_rewrite_remains_eligible(self):
        old = "[URL Rewrite]\n^a _ reject\n"
        new = old+"^b _ reject\n"
        self.assertEqual(auto.validate_delta(old.encode(),new.encode(),old,new)["added_active_entries"],1)

    def test_large_delta_blocks(self):
        extra = "[URL Rewrite]\n"+"\n".join("^https://new"+str(i)+".example/ _ reject" for i in range(26))+"\n"
        self.assertBlocked(OLD.replace(b"[Script]", extra.encode()+b"[Script]"), "large_rule_delta_requires_review")

    def test_unknown_directives_and_lost_author_block(self):
        self.assertBlocked(b"#!new-directive=anything\n"+OLD, "upstream_directive_set_changed")
        self.assertBlocked(OLD.replace(b"#!author=Original author", b"#!author=Other author"), "upstream_attribution_changed")

    def test_untrusted_code_invalid_syntax_html_and_secret_rejected(self):
        for new in (b"<html>Error</html>", OLD+b"[Script]\n$(touch /tmp/executed)\n", OLD+b"# password = secret\n"):
            with self.subTest(new=new): self.assertBlocked(new)

    def test_only_exact_fmz_manifest_allowed(self):
        for changed in ({"sources": self.manifest["sources"]*2}, {"redistribution": {"approved": False}}):
            json_write(self.root/"sources-fmz.json", {**self.manifest, **changed})
            self.assertBlocked(OLD)
        for value in (auto.UPSTREAM+"main/"+auto.SOURCE_PATH, "https://evil.example/x"):
            manifest = deepcopy(self.manifest); manifest["sources"][0]["immutable_url"] = value
            json_write(self.root/"sources-fmz.json", manifest)
            self.assertBlocked(OLD)

    def test_artifact_carries_license_without_publishing_or_changing_it(self):
        files, sha = self.package_ready()
        self.assertEqual(files[auto.LICENSE_PATH], LICENSE)
        self.assertEqual((self.package/auto.LICENSE_PATH).read_bytes(),LICENSE)
        self.assertIn(auto.LICENSE_PATH,auto.PACKAGE_FILES)
        self.assertNotIn(auto.LICENSE_PATH,auto.PUBLIC_FILES)
        self.assertEqual(json.loads(files["reports/fmz200-update.json"])["license_sha256"],digest(LICENSE))
        self.assertEqual(auto.verify_package(self.package,sha,BASE_SHA)[auto.LICENSE_PATH],LICENSE)

    def test_package_roundtrip_and_commit_binding(self):
        files, sha = self.package_ready()
        self.assertEqual(auto.verify_package(self.package, sha, BASE_SHA), files)
        with self.assertRaisesRegex(auto.Blocked, "package_binding_mismatch"):
            auto.verify_package(self.package, sha, OLD_SHA)
        with self.assertRaisesRegex(auto.Blocked, "package_digest_mismatch"):
            auto.verify_package(self.package, "f"*64, BASE_SHA)

    def test_package_tampering_and_extra_executable_block(self):
        _, sha = self.package_ready()
        path = self.package/auto.MODULE_PATH
        original = path.read_bytes(); path.write_bytes(original+b"# tampered\n")
        with self.assertRaisesRegex(auto.Blocked, "package_file_hash_mismatch"):
            auto.verify_package(self.package, sha, BASE_SHA)
        path.write_bytes(original)
        (self.package/"injected.py").write_text("raise RuntimeError('do not run')")
        with self.assertRaisesRegex(auto.Blocked, "unexpected_package_path"):
            auto.verify_package(self.package, sha, BASE_SHA)

    def test_symlink_and_manifest_substitution_block(self):
        _, sha = self.package_ready()
        path = self.package/"NOTICE.md"; path.unlink(); path.symlink_to(self.root/auto.MODULE_PATH)
        with self.assertRaisesRegex(auto.Blocked, "package_symlink_forbidden"):
            auto.verify_package(self.package, sha, BASE_SHA)

    def test_package_never_overwrites_prior_candidate(self):
        files, sha = self.package_ready()
        with self.assertRaisesRegex(auto.Blocked, "package_destination_must_be_new"):
            auto.write_package(self.package, files, BASE_SHA)
        self.assertEqual(auto.verify_package(self.package, sha, BASE_SHA), files)

    def test_workflow_has_only_one_contents_write_job_and_pinned_actions(self):
        path = Path(__file__).resolve().parents[1] / ".github/workflows/update.yml"
        text = path.read_text()
        self.assertEqual(text.count("contents: write"), 1)
        self.assertIn("permissions:\n  contents: read", text)
        self.assertIn("needs: prepare", text)
        self.assertIn("cron: '37 3 * * *'", text)
        self.assertIn("workflow_dispatch:", text)
        self.assertNotIn("pull_request_target", text)
        self.assertNotIn("workflow_run:", text)
        self.assertEqual(text.count("persist-credentials: false"), 2)
        import re
        for action in re.findall(r"uses: ([^\s#]+)", text):
            self.assertRegex(action, r"^actions/[a-z-]+@[0-9a-f]{40}$")
        self.assertEqual(text.count("GITHUB_TOKEN:"), 1)
        self.assertIn("GITHUB_TOKEN: ${{ github.token }}", text)

    def test_cli_status_never_echoes_untrusted_exception_or_workflow_commands(self):
        report = self.root/"status.json"
        output, summary = self.root/"output", self.root/"summary"
        with patch.dict(os.environ, {"GITHUB_OUTPUT":str(output), "GITHUB_STEP_SUMMARY":str(summary)}):
            with patch.object(auto, "prepare", side_effect=ValueError("SECRET\n::set-output name=changed::true")):
                code = auto.main(["prepare", "--base-sha", BASE_SHA, "--report", str(report)])
        self.assertEqual(code,2)
        self.assertEqual(output.read_text(),"changed=false\n")
        for p in (report,output,summary):
            self.assertNotIn("SECRET",p.read_text())
            self.assertNotIn("::set-output",p.read_text())

    def test_prepare_fetches_only_fixed_immutable_source_and_license(self):
        ref = {"ref":"refs/heads/main", "object":{"type":"commit", "sha":NEW_SHA}}
        with patch.object(auto, "github_json", return_value=ref), patch.object(auto, "download", side_effect=[OLD, OLD, LICENSE]) as get:
            result = auto.prepare(self.root, self.package, BASE_SHA)
        self.assertEqual(result["status"], "ready")
        self.assertEqual([call.args[0] for call in get.call_args_list], [auto.UPSTREAM+OLD_SHA+"/"+auto.SOURCE_PATH, auto.UPSTREAM+NEW_SHA+"/"+auto.SOURCE_PATH, auto.UPSTREAM+NEW_SHA+"/LICENSE"])

    def test_failed_fetch_preserves_tracked_files_and_has_no_package(self):
        before = (self.root/auto.MODULE_PATH).read_bytes()
        with patch.object(auto, "download", side_effect=OSError("private upstream response")):
            rc = auto.main(["prepare", "--root", str(self.root), "--package", str(self.package), "--base-sha", BASE_SHA, "--report", str(self.root/"status.json")])
        self.assertEqual(rc, 2)
        self.assertFalse(self.package.exists())
        self.assertEqual((self.root/auto.MODULE_PATH).read_bytes(), before)
        report = (self.root/"status.json").read_text()
        self.assertNotIn("private upstream", report)

    def test_api_destination_and_token_never_follow_remote_url(self):
        for url in ("https://evil.example/x", auto.UPSTREAM+NEW_SHA+"/LICENSE"):
            with self.assertRaisesRegex(auto.Blocked, "unapproved_api_destination"):
                auto.github_json(url, token="not-real")
        with self.assertRaisesRegex(auto.Blocked, "token_destination_blocked"):
            auto.github_json(auto.UPSTREAM_REF, token="not-real")

    def publish_env(self):
        return patch.dict(os.environ, {"GITHUB_REPOSITORY":auto.REPOSITORY, "GITHUB_REF":"refs/heads/main", "GITHUB_EVENT_NAME":"schedule"})

    def test_publish_wrong_repo_branch_or_context_never_writes(self):
        _, sha = self.package_ready()
        for env in ({"GITHUB_REPOSITORY":"fork/other"}, {"GITHUB_REF":"refs/heads/other"}, {"GITHUB_EVENT_NAME":"pull_request"}):
            with self.publish_env(), patch.dict(os.environ, env), patch.object(auto,"github_json") as api, self.assertRaises(auto.Blocked):
                auto.publish(self.package, sha, BASE_SHA, "not-real")
            api.assert_not_called()

    def test_main_race_blocks_before_any_write(self):
        _, sha = self.package_ready()
        with self.publish_env(), patch.object(auto,"github_json",return_value={"object":{"sha":OLD_SHA}}) as api:
            with self.assertRaisesRegex(auto.Blocked,"main_advanced_rebuild_required"):
                auto.publish(self.package, sha, BASE_SHA, "not-real")
        self.assertEqual(api.call_count,1)
        self.assertNotIn("method",api.call_args.kwargs)

    def test_publish_uncertain_final_update_is_not_retried(self):
        _, sha = self.package_ready()
        calls = []
        def fake(url, **kw):
            calls.append((url,kw))
            endpoint=url.split("/git/")[1]
            if endpoint=="ref/heads/main": return {"object":{"sha":BASE_SHA}}
            if endpoint=="commits/"+BASE_SHA: return {"tree":{"sha":"4"*40}}
            if endpoint=="blobs": return {"sha":"5"*40}
            if endpoint=="trees": return {"sha":"6"*40}
            if endpoint=="commits": return {"sha":"7"*40}
            if endpoint=="refs/heads/main": raise OSError("uncertain secret response")
            raise AssertionError(endpoint)
        with self.publish_env(),patch.object(auto,"github_json",side_effect=fake):
            with self.assertRaisesRegex(auto.PublicationUncertain,"publication_unconfirmed_check_main"):
                auto.publish(self.package,sha,BASE_SHA,"not-real")
        self.assertEqual(len([kw for _,kw in calls if kw.get("method")=="PATCH"]),1)

    def test_no_token_stops_before_api_access(self):
        _, sha = self.package_ready()
        with self.publish_env(),patch.object(auto,"github_json") as api:
            with self.assertRaisesRegex(auto.Blocked,"missing_builtin_workflow_token"):
                auto.publish(self.package,sha,BASE_SHA,None)
        api.assert_not_called()

    def test_publish_single_atomic_commit_exact_paths_no_force(self):
        files, sha = self.package_ready()
        calls = []
        def fake(url, **kw):
            calls.append((url, kw))
            endpoint=url.split("/git/")[1]
            if endpoint=="ref/heads/main": return {"object":{"sha": "7"*40 if any(u.endswith("refs/heads/main") for u,_ in calls) else BASE_SHA}}
            if endpoint=="commits/"+BASE_SHA: return {"tree":{"sha":"4"*40}}
            if endpoint=="blobs": return {"sha":"5"*40}
            if endpoint=="trees": return {"sha":"6"*40}
            if endpoint=="commits": return {"sha":"7"*40}
            if endpoint=="refs/heads/main": return {"object":{"sha":"7"*40}}
            raise AssertionError(endpoint)
        with self.publish_env(),patch.object(auto,"github_json",side_effect=fake):
            result=auto.publish(self.package,sha,BASE_SHA,"not-real")
        self.assertEqual(result["status"],"published")
        tree=next(kw["payload"] for url,kw in calls if url.endswith("/trees"))
        self.assertEqual({e["path"] for e in tree["tree"]},set(auto.PUBLIC_FILES))
        commit=next(kw["payload"] for url,kw in calls if url.endswith("/commits"))
        self.assertEqual(commit["parents"],[BASE_SHA])
        updates=[kw for url,kw in calls if kw.get("method")=="PATCH"]
        self.assertEqual(len(updates),1)
        self.assertEqual(updates[0]["payload"],{"sha":"7"*40,"force":False})


if __name__ == "__main__":
    unittest.main()
