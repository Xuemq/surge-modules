# Surge 模块审查与合并工具

面向 `Xuemq/surge-modules` 的可审查合并流程：固定来源、检查变更、保守转换 Quantumult X 配置、检查冲突，并在检查通过后生成本地候选模块。

**当前不是可直接订阅的成品模块仓库。** 实现已按仓库所有者的要求启动，但来源许可、转换兼容性与冲突处理仍需审查。没有发布稳定模块，也没有自动将候选版本提升为稳定版本。

## 当前边界

- 仓库只收录本项目原创工具、测试、文档和来源元数据。上游配置、脚本正文及生成模块在许可问题澄清前不得提交。
- 来源由 [`sources.json`](sources.json) 中的完整 URL 和锁定的 SHA-256 指定；不把搜索到的同名文件当作替代品，不静默跟随上游脚本依赖。
- 下载文件、缓存、审查报告及候选模块保留在被 `.gitignore` 排除的工作目录。忽略规则只是防误提交措施，发布前仍须检查暂存区。
- 不读取用户的 Surge 主配置、订阅凭据、MITM CA 私钥或口令，不上传个人配置，也不修改设备上的 Surge 设置。
- 自动流程只检查并报告。不会推送分支、创建 PR、上传上游文件为 Actions artifact，或发布生成模块。

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

## 自动检查（尚未实现）

当前没有提交或启用 GitHub Actions 工作流。每日上游检查、冲突草稿 PR 和稳定模块发布仍是后续工作，不能将这个仓库当作已经自动更新的订阅源。

## 当前验证结果

2026-10-17：本地运行 57 项合成单元测试，全部通过。真实来源审查仍被阻断：墨鱼有 29 条指令尚待兼容性核验，fmz200 有远程映射、未定义参数及脚本名称等问题待核对。尚未生成可直接使用的三源合并模块。

## Surge 兼容性与已知限制

本次审查的 fmz 来源含有 `[Body Rewrite]` 与 jq 规则，不能假定旧版 Surge iOS 可用。官方手册列出的 Body Rewrite 起始版本为 iOS 5.10.0，jq Body Rewrite 为 iOS 5.14.0；实际候选文件还可能要求其他更高版本的功能，应按最终内容核对。[Body Rewrite 官方说明](https://manual.nssurge.com/http/body-rewrite.html)

这里的校验是文本、结构和已实现规则的静态检查，并未在真实 Surge iOS 上执行，也没有正则表达式等价性证明或完整的匹配集合重叠检查。不同正则可能匹配相同请求；顺序改变可能改变行为。真实应用、响应正文、脚本运行时与其他已启用模块仍需在设备上验证。

模块会覆盖或插入当前配置的部分设置。HTTPS 改写还依赖相关主机的 MITM 配置和设备信任状态。工具不会替用户建立证书信任或扩大解密范围。[模块说明](https://manual.nssurge.com/profile/module.html) · [MITM 说明](https://manual.nssurge.com/http/mitm.html)

## 来源与许可

来源文件的准确地址、锁定哈希和当前审查信息以 [`sources.json`](sources.json) 为准。初步审查存在 GPL-2.0、GPL-3.0 线索及未找到明确许可的来源；适用范围、版本选择、再分发条件和混合后的义务仍未解决。可访问或可下载不代表可重新发布。

在这些问题澄清前：

1. 不提交上游原文、转译后的规则或合并产物。
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
