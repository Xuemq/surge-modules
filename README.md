# Surge 模块审查与合并工具

面向 `Xuemq/surge-modules` 的可审查合并流程：固定来源、检查变更、保守转换 Quantumult X 配置、检查冲突，并在检查通过后生成本地候选模块。

**当前提供 fmz200 单来源优化候选，完整三源合并仍在审查。** 原始来源许可、跨来源冲突与墨鱼剩余转换项分别处理；不会自动把候选提升为稳定版本。

## 当前边界

- 工具、测试和文档为本项目原创。fmz200 单来源派生模块须连同上游 GPL-3.0、署名和修改说明发布；许可未解决的三源混合内容仍不得提交。不会打包远程脚本正文。
- 来源由 [`sources.json`](sources.json) 中的完整 URL 和锁定的 SHA-256 指定；不把搜索到的同名文件当作替代品，不静默跟随上游脚本依赖。
- 下载文件、缓存、审查报告及候选模块保留在被 `.gitignore` 排除的工作目录。忽略规则只是防误提交措施，发布前仍须检查暂存区。
- 不读取用户的 Surge 主配置、订阅凭据、MITM CA 私钥或口令，不上传个人配置，也不修改设备上的 Surge 设置。
- 自动流程只检查并报告。不会推送分支、创建 PR、上传上游文件为 Actions artifact，或发布生成模块。

## 首个候选：仅优化 fmz200

订阅：[去广告优化 · fmz200](https://raw.githubusercontent.com/Xuemq/surge-modules/main/modules/fmz200.optimized.sgmodule)。模块内的名称和说明明确标注 fmz200 单来源、安全去重、参数修复、范围精简以及尚未实机验证；原始作者署名保留。

已实现独立的单来源优化命令。此候选不混入 blackmatrix7 或墨鱼规则；发布时须同时提供 fmz200 的原始 GPL-3.0 许可与修改说明。完整三源构建仍单独受许可和冲突门禁约束。

```sh
python -m surge_merge optimize-base .cache/fmz200.source --policy fmz-policy.json --output work/fmz200.optimized.sgmodule --report work/fmz200-report.json
```

优化保留上游作者与说明、原有顺序及不同操作，只去除安全的完全重复项。重复脚本标签使用确定性唯一名；缺失参数采用上游可核实默认值；已过时的 Sparkle 参数改为作者原生 Surge 模块采用的 JSON 对象。失效项删除只能使用绑定原行哈希和证据的策略记录。网络超时、403、年代较早均不构成删除理由。

明确选择的范围排除另存于 `fmz-policy.json` 的 `scope_exclusions`，绑定源文件哈希及每条原始段名、行号、行哈希；它不代表规则已经失效。任何目标漂移、重复决定或与其他修复冲突都会阻断构建。此策略不按应用名、共享域名或通配符批量删除，也不能移除 MITM/General 设置。公开策略仅记录精确规则选择，不包含个人应用清单或截图。

`.github/workflows/ci.yml` 已提供提交、PR 与手动测试，只读权限。另提供每日来源检查；草稿 PR/稳定发布自动化仍未接入。现有候选只通过静态检查和合成测试，未在真实 Surge iOS 运行。

## 本地使用

在仓库根目录使用 Python 3.11 或更新版本。工具仅依赖 Python 标准库。

先运行原创测试：

```sh
python -m unittest discover -s tests -v
```

下载并检查清单中的固定来源：

```sh
python -m surge_merge fetch --manifest sources.json --cache .cache
python -m surge_merge audit --manifest sources.json --cache .cache --report work/report.json
```

阅读报告并处理阻断项后，尝试生成本地候选文件：

```sh
python -m surge_merge build --manifest sources.json --cache .cache --output work/candidate.sgmodule
```

`build` 的成功只代表工具允许输出本地候选文件。哈希不匹配、无法支持的转换、未解决的冲突会阻止构建；再分发许可与发布资格另行检查。任何一次静态检查通过都不代表已经获准公开发布。

单独检查一份已合法取得的 Quantumult X 配置：

```sh
python -m surge_merge convert-qx INPUT --output work/moyu.sgmodule --report work/conversion.json
```

把 `INPUT` 替换为本地输入路径。转换采用保守策略：仅转换明确支持的语法；遇到不支持的指令或未确认的脚本兼容性时停止，而不是丢弃规则后冒充完整转换。检查报告中的阻断项，不能仅凭文件存在判定成功。输入中的远程 JavaScript 也不能因为改成 Surge 的声明格式，就被认定兼容 Surge。

只检查上游是否变化，不生成模块：

```sh
python -m surge_merge check-updates --manifest sources.json --report work/update-status.json
```

此命令只访问清单中明确列出的来源 URL，比较锁定哈希，输出经过限制的 JSON 元数据状态。不会把上游正文加入仓库；发现变化也不会自动更新锁定值。非零退出码表示检查失败或存在阻断，需查看报告。

所有命令的最终参数以 `python -m surge_merge --help` 及相应子命令的 `--help` 为准。不要为让流程变绿而删除阻断记录。

## 自动检查

已提供只读权限的 ci.yml，运行提交、PR 和手动测试；是否已在远端运行，以仓库 Actions 实际记录为准。update.yml 提供每日 UTC 03:37 和手动的 fmz 来源检查，使用单来源 sources-fmz.json，不受三源许可门禁干扰。发现变更或下载失败时作业失败并输出受限元数据摘要，保留已发布文件和已审核锁定值；没有写权限、上传下载正文、生成PR或自动发布步骤。GitHub定时可能延迟。不能将此检查误认为自动更新订阅内容。

## 当前验证结果

2026-10-17：本地94项合成测试与Python编译检查全部通过。fmz单来源候选通过静态校验，267条安全重复项已删除，标签和缺失参数已修复。按明确选择另外排除9条应用专用规则，其余活动规则和顺序保持不变，MITM范围未改。全部110个公共脚本/资源依赖可读取，但这不证明所有广告规则仍有效。墨鱼506条指令中503条可转换，剩余两个仅在QX生效的脚本及一条TestFlight地区改写继续阻断完整转换。三源合并尚未完成；未执行Surge实机测试。

## Surge 兼容性与已知限制

本次审查的 fmz 来源含有 `[Body Rewrite]` 与 jq 规则，不能假定旧版 Surge iOS 可用。官方手册列出的 Body Rewrite 起始版本为 iOS 5.10.0，jq Body Rewrite 为 iOS 5.14.0；实际候选文件还可能要求其他更高版本的功能，应按最终内容核对。[Body Rewrite 官方说明](https://manual.nssurge.com/http/body-rewrite.html)

这里的校验是文本、结构和已实现规则的静态检查，并未在真实 Surge iOS 上执行，也没有正则表达式等价性证明或完整的匹配集合重叠检查。不同正则可能匹配相同请求；顺序改变可能改变行为。真实应用、响应正文、脚本运行时与其他已启用模块仍需在设备上验证。

模块会覆盖或插入当前配置的部分设置。HTTPS 改写还依赖相关主机的 MITM 配置和设备信任状态。工具不会替用户建立证书信任或扩大解密范围。[模块说明](https://manual.nssurge.com/profile/module.html) · [MITM 说明](https://manual.nssurge.com/http/mitm.html)

## 来源与许可

来源文件的准确地址、锁定哈希和当前审查信息以 [`sources.json`](sources.json) 为准。初步审查存在 GPL-2.0、GPL-3.0 线索及未找到明确许可的来源；适用范围、版本选择、再分发条件和混合后的义务仍未解决。可访问或可下载不代表可重新发布。

在这些问题澄清前：

1. 不提交许可未解决的混合原文、转译规则或三源合并产物。单独的 fmz200 派生版本按其 GPL-3.0 及署名/修改说明要求处理。
2. 不凭推测给来源重新标注许可证，也不以本工具的原创实现替代上游授权。
3. 保留必要的来源元数据；对每项许可、署名、版权通知和派生文件义务逐项留证。
4. 即使哈希、转换及冲突检查全部通过，也继续阻止未经许可审查的公开发布。

完整的人工审查步骤见 [`docs/REVIEW.md`](docs/REVIEW.md)。

## 官方参考

- [Surge Module](https://manual.nssurge.com/profile/module.html)
- [Body Rewrite 与 jq](https://manual.nssurge.com/http/body-rewrite.html)
- [HTTPS Decryption / MITM](https://manual.nssurge.com/http/mitm.html)
- [Surge Scripting](https://manual.nssurge.com/scripting/overview.html)

本项目不隶属于 Surge 或任何上游规则作者，也不以合并结果取代上游维护者的说明。
