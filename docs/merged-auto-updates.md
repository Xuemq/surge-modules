# 三来源的保守自动更新

固定地址：`modules/merged.optimized.sgmodule`。单来源回退地址 `modules/fmz200.optimized.sgmodule` 有独立策略和发布清单。

`.github/workflows/update-merged.yml` 每天 UTC 03:37（北京时间 11:37）运行，也支持手动运行；相关工具、策略或工作流推送到 main 时会验证一次。该机制实际抓取、构建、测试并在全部门禁通过后发布，不只是检查上游版本。未通过则保留最后成功版本；不会跳过某个来源来假装更新完成。

## 可自动迁移的内容

- fmz200 和 blackmatrix7 的新内容先解析分支提交，再按不可变提交 URL 下载。墨鱼来源无相同的 Git 提交接口，使用固定 HTTPS 地址读取，并把本次确切源文件保存到 `upstream/moyu.source`。
- 使用已发布文件和旧锁定源完整重建基线，要求模块逐字节相同。新包使用独立 `merged-policy.json`，不更改 fmz 单来源策略。
- 已审规则只能凭完整段名、行内容哈希或解析后的条目 ID 重定位。要求旧、新目标唯一；缺失、改写、重复或数量歧义都会阻断。不能用相似名称、域名猜测、模糊匹配或静默删除来通过门禁。
- 保留 9 条 fmz 精确范围排除，以及两个补充来源中的对应精确排除、TestFlight 排除、两项原生响应适配的全部参数和哈希。
- 现有 453 项冲突决定、166 项补充冲突排除和 173 对有限重叠见证保留原语义；只更新必要的行号与阶段哈希，不生成新的冲突决定或例外。构建器重新检查这些决定及见证。
- 允许小范围、可解析的 URL Rewrite 拒绝规则增删，以及未受精确决定约束的条目删除；新增或改写外部资源、脚本、Rule 路由、Map Local 响应、重定向、Header Rewrite 和 Body Rewrite 定义均需要人工复核。Map Local 即使引用已有 URL 或看起来是静态正文，也不能绕过状态码、Location、Refresh、Set-Cookie 或活动正文的人工复核。已有脚本即使 URL 不变，修改匹配、阶段、参数、请求体或其他设置也会阻断。
- 保留已有条目的相对顺序和重复次数；检查字面冲突、MITM、General、语义元数据、作者信息和变更数量。各转换阶段和最终模块都检查，避免把危险改动藏在转换或去重阶段。有限 URL 见证不解释 Rule 路由语言，因此连新的 DOMAIN 拒绝规则也不自动接受，防止绕过已知基线重叠门禁。
- 已审序列化修复保存在 `merged-policy.json` 的 `serialization_repairs` 中；更新只能完整保留该策略，不能重算修复决定。基线先重建修复后的已发布模块，新源仍须匹配每个唯一条目 ID；目标缺失、重复或改变时阻断，不能静默恢复坏行。版本化 `scripts/header-status-v2.js` 的固定仓库 URL 和文件哈希在准备及发布包验证阶段均检查；自动更新不会改写 v1 或 v2 适配器。此轮修复仅适用于三源模块，fmz 回退订阅保持原样。
- 已观察到的两份许可、两份 blackmatrix7 README 和墨鱼原始前 20 行通知必须逐字节不变；上游通知变化不自动解释或接受。来源评论原文会随当前源文件归档。

上述“范围保留”针对已经精确审过的条目，不是识别任意新规则属于哪个应用的语义分类器。有限见证仅覆盖已知 URL；它们不能证明所有正则之间没有重叠。新规则仍可能改变应用行为。

## 发布边界

准备任务只有 `contents: read`，不接收写入令牌；上游内容只当数据，不运行上游 JavaScript、jq 或 shell。固定 HTTPS 目的地、不跟随重定向、单文件上限 8 MiB，单次网络请求超时 30 秒。准备命令在 Linux runner 中另设 180 秒总预算，包含解析和有限 Python 正则重放；超时不发布。工作流还有外层任务超时。

只有独立发布任务有 `contents: write`。它不下载上游，只验证本次 artifact 的整体哈希、精确路径、逐文件大小/哈希、源码提交绑定及内部记录。使用平台自带短期 `GITHUB_TOKEN`，不创建 PAT、密钥、长期凭证或新 secrets。

可变发布清单只有：

- `modules/merged.optimized.sgmodule`
- `sources-merged.json`、`merged-policy.json`、`upstream/moyu.source`
- `reports/merged-build-report.json`、`reports/merged-update.json`
- `notices/fmz200-source-comments.txt`、`notices/blackmatrix7-source-comments.txt`、`notices/moyu-source-comments.txt`

固定许可、通知和本仓库原生适配器包含在 artifact 中用于验证，不在自动提交的写入清单中。自动任务不能更改工具、工作流、README、fmz 回退模块或其政策。

两个更新工作流使用同一 concurrency group，禁止取消正在运行的任务。排队任务开始时只 checkout 当时的可信 main，记录一次确切 SHA；准备包、验证、发布工具 checkout 与提交 parent 全绑定同一 SHA。发布前若 main 已推进就阻断，不重新读取代码后沿用旧包，不自动 rebase。最终以 `force: false` 一次原子更新 main；最终响应不确定时不得盲目重试，应先查看 main。

GitHub 默认 concurrency 队列只保留一个待运行项，快速连续触发可能替换较旧的待运行项；下一次日程或手动运行会再检查。它不是每个事件必达的消息队列。配置依据：[GitHub concurrency](https://docs.github.com/en/actions/how-tos/write-workflows/choose-when-workflows-run/control-workflow-concurrency)、[GitHub workflow 安全建议](https://docs.github.com/en/actions/reference/security/secure-use)。

## 复现和失败处理

按 `sources-merged.json` 下载两个不可变源，使用仓库内墨鱼快照填充 `.cache/{fmz200,blackmatrix7,moyu}.source`，执行：

```sh
python3 -m unittest discover -s tests -v
python3 -m surge_merge.combined --bundle merged-policy.json --cache .cache --output-dir work/replay
```

网络准备只生成候选，不改仓库：

```sh
python3 -m surge_merge.merged_update prepare --base-sha "$(git rev-parse HEAD)"
```

成功变化的记录写入 `reports/merged-update.json`；没有变化不提交。首次运行可以只补齐更新记录，用于验证真实的发布路径。失败原因以固定代码写入 `work/merged-auto-status.json` 和 Actions 摘要，不把远端错误正文、规则片段或凭证带入日志。

遇到策略目标变化、新冲突、通知变化或不支持语法，需要重新人工审查确切源快照和决定，再更新锁定政策；不能仅改哈希使任务变绿。下载失败和未知发布状态也不能算更新成功。

## 保证范围

这不是 Surge iOS 或应用实机验证，也不是广告拦截有效性、任意正则等价性或零误拦截保证。引用脚本/资源仍是外部 URL；同一 URL 的远端正文可以独立变化，本流程不持续监测或锁定所有这些正文。原生适配器文件仅检查当前仓库中的审核哈希。

用户要求公开托管不等于第三方作者授予新许可。此流程记录已观察到的原始许可和通知，不声称已有额外作者许可，不给混合内容声明统一许可证；具体说明见 [合并来源声明](merged-notice.md)。
