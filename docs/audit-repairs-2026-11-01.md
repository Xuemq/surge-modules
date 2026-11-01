# Reviewed conflict and runtime-contract repairs

These are static, source-bound repairs to the published three-source and single-source outputs. They are not a claim that every app endpoint or remote script has been device-tested.

## Applied decisions

- Remove 406 DOMAIN / DOMAIN-SUFFIX entries only when an earlier, retained DOMAIN-SUFFIX with the same REJECT action covers the hostname. The builder independently checks each coverage proof.
- Enable binary-body-mode for the existing Baidu Map protobuf decoder; remove the fully shadowed supplementary binding in the merged output.
- Correct the Umetrip scheme and grouping so that the IP branch is constrained to the same exact gateway path. Do not add guessed `.com.cn` MITM wildcards.
- Remove the fmz AMDC header handler whose Surge branch returns unchanged. The merged HTTP fallback can then operate; this does not add HTTPS coverage to that fallback.
- Correct the malformed KFC hostname in the single-source output; in the merged output remove it in favor of the already retained correct reject.
- Preserve the current first-matching response-script priority for iQiyi, Taobao, Coolapk, Zhihu and the 555 movie fallback. Remove fully shadowed bindings; explicitly subtract prior patterns from partial fallbacks. Unique HTTP, host and path coverage remains. These fallbacks assume the module's preceding bindings stay enabled; manually disabling individual scripts can remove the corresponding coverage.
- Remove two Didi response bindings already superseded by URL reject. Trim the rejected Tencent news, Pangolin and Kuaishou branches while retaining the other live branches and shared script files.
- Allow HTTPS JD `functionId=start` responses to reach the existing JSON cleaner instead of replacing them with GIF/blank text. Keep HTTP handling and the independent `queryMaterialAdverts` mock. This is a deliberate behavior repair, not merely equivalent deduplication.
- Add only the four explicitly reviewed hosts needed by existing HTTPS scripts: `mcsp.cloudpnr.com`, `saas-ad.cloudpnr.com`, `iqushangwang.8quan.com`, `vue3-api.zhixiny.cn`.

All transformations bind exact entry identities and witnesses. Missing, changed or ambiguous anchors fail closed. The pre-existing source, merge, scope, serialization, license and update guards remain. The 872 previously selected entries remain excluded, and no daily schedule is re-enabled.

## Not resolved by static evidence

- Other Map Local overlaps with different mock bodies remain as reviewed inherited strategies. No evidence proves that replacing JSON, GIF and blank responses with a single policy is safe across apps. Map Local/response-script interactions need a representative device capture before further consolidation.
- The supplementary Umetrip `.com.cn` target has not been confirmed by a current request capture. Its MITM scope was not expanded.
- Legacy string-valued `$done` statuses in remote scripts need Surge runtime verification. Remote script bodies are not vendored or rewritten here.
- Downloadability and JavaScript syntax do not prove that an endpoint, response schema or ad-removal behavior is current. VPN restarts cannot be diagnosed from rule count alone.

## Verification

The release is checked with exact output/order diffs, domain coverage witnesses, representative positive/negative URL tests, binary-mode and JSON-handler configuration checks, Python tests and compilation, ICU regex compilation, independent review, and both guarded update preparations. Actual GitHub workflow outcomes and raw bytes are verified after publication. App behavior and MITM certificate setup still need real-device evidence.
