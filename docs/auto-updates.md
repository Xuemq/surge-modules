# fmz200 安全自动更新

稳定订阅地址始终为：
https://raw.githubusercontent.com/Xuemq/surge-modules/main/modules/fmz200.optimized.sgmodule

`.github/workflows/update.yml` 每日 UTC 03:37 执行，也支持 Actions → Safely update fmz200 module → Run workflow。自动更新代码、测试或单来源策略在 `main` 上变更时也会运行一次，用于验证新配置。这里只更新已获准发布的 fmz200 单来源模块；三源合并、个人配置、上游脚本正文不在自动发布范围内。

## 工作流程

1. 只读 `prepare` 作业与三源更新共享串行队列；排队结束、任务开始时检出当前可信 `main`，记录确切提交 SHA，再运行全部原创测试及 Python 编译检查。此 SHA 绑定准备包、发布工具检出及提交 parent，发布时不自动追随新的 main。
2. 从 `sources-fmz.json` 的不可变 URL 下载已发布来源，验证锁定 SHA-256 和字节数；用当前策略重建，必须与已发布模块逐字节一致。
3. 查询 fmz200 官方仓库的 `main` 提交，再用该提交的不可变 URL 下载模块和 LICENSE。拒绝重定向、非 UTF-8、HTML、凭据内容及超过 8 MiB 的文件。不下载或执行引用的脚本、jq 或正则表达式。
4. 在内存中迁移精确策略，构建新模块并检查下述门禁。全部通过才准备发布包；仓库中的文件此时没有被改写。
5. 上传的临时 artifact 仅含六个准许发布的 fmz 文件、未修改的 GPL-3.0 许可副本和包清单，保留 1 天。不上传缓存、原始来源、脚本正文、个人应用清单或三源内容。
6. 单独的 `publish` 作业获得 `contents: write`，其余作业仅有只读权限。重新检出同一固定提交，检查该次运行传递的包 SHA-256、源提交绑定、每个文件的哈希和字节数、完整路径白名单，以及模块静态解析。
7. 只使用 GitHub 内置、短期 `GITHUB_TOKEN` 创建一个包含所有发布文件的 Git 提交。父提交必须仍是此次测试的 `main`；最后用 `force: false` 更新分支，避免覆盖别人的新提交。没有 PAT、持久凭据、新增 secret、PR 或维护者消息。
8. 再读取 `main` 确认发布结果。网络中断导致结果不确定时报告 `publication_unconfirmed`，不盲目重试。应先查看 `main` 和 Actions 记录。

首次启用时会写入自动发布记录并刷新说明，即使上游规则没有变化。这可以验证实际写入路径，但模块字节保持不变。以后内容完全相同的运行不会产生提交。GITHUB_TOKEN 生成的提交通常不会再次触发 push 工作流，因此全部测试在发布前执行。

## 保守门禁

以下情况需要人工审查，不能为了让流程通过而删除阻断项：

- 任一已选范围排除项缺失、正文改变、跨段移动或出现多个相同目标。允许的唯一自动迁移是相同段名与行哈希的唯一目标移动行号。九项选择不按应用名、共享域名、通配符或近似文本扩大。
- 已审核参数修复或确认失效删除项的精确正文、所在段或出现次数变化。重复修复目标必须保留原有次数。
- 任何新增脚本定义或脚本匹配模式、请求/响应阶段、正文访问、参数、超时等定义变化，即使 script-path 没有变化也需要审查。
- 非 reject 的 URL Rewrite 重定向/透明改写或 Header Rewrite 定义新增或改变，防止无审查地改变请求路由或出站请求头。
- 任何 Rule 路由或 Body Rewrite 定义新增或改变；新的 DIRECT、域名拒绝或请求/响应正文处理均需要复核，语法有效不代表行为已获准。
- 任何 Map Local 定义新增或改变，包括匹配、正文、状态码和头部；同一外部资源 URL 也不能作为复核替代。此门禁防止通过 Location、Refresh、Set-Cookie 或活动正文绕过重定向和头部检查。已审完全相同定义可保留，删除仍受其他门禁约束。
- 新的或正文/顺序改变的已知同键冲突、重复脚本触发器或跨段同一请求模式冲突。原有冲突仅在身份与顺序完全相同时继承，不称作已证明无冲突。
- MITM 或 General 设置变化、模块语义参数/默认值变化、新元指令、作者署名变化或新远程脚本/资源 URL。
- 仍存在的规则相对顺序变化，包括 Body/Header Rewrite 每次重复出现的位置和次数；新增或删除数量分别超过旧活动规则数量的 10%（小配置下最低阈值为 25 条）。这一阈值用于阻止截断或大范围异常更新，不是正确性证明。
- 未支持语法、未声明参数、无证据默认值、模块名/说明丢失、来源/许可/hash/字节数校验失败。
- 新 LICENSE 与仓库中已发布的 GPL-3.0 文件不一致；多源清单或未获准再分发。
- 发布包增加白名单外文件、符号链接或改动工具、测试、工作流、许可文件；包摘要或文件哈希不一致。
- `main` 已经前进，或者仓库规则不允许工作流写入。不会降低分支保护或改用强制推送。

自动新增/改写仅允许通过全部门禁的 URL Rewrite reject 规则；其余规则保持精确已审定义，或在其他门禁允许时删除。通过门禁后才会替换订阅内容。失败的下载、构建、测试和发布前校验不会修改已发布模块与来源锁。最终分支更新是原子的，不会出现模块已更新而策略尚未更新的部分发布。最终 API 响应不确定与明确校验失败分开报告。

## 发布与复现文件

自动发布只允许改动：

- `modules/fmz200.optimized.sgmodule`
- `sources-fmz.json`
- `fmz-policy.json`
- `reports/fmz200-build-report.json`
- `reports/fmz200-update.json`
- `NOTICE.md`

`licenses/fmz200-GPL-3.0.txt` 继续保留，自动更新不修改它；artifact 携带相同许可副本，但发布提交的路径白名单不包含许可文件。`reports/fmz200-scope-diff.json` 是首次九项范围精简的历史证据；`sources.json` 是三源研究的独立锁，不由单源更新同步。

本地只准备候选包，不发布：

```sh
python -m unittest discover -s tests -v
python -m compileall -q surge_merge tests
python -m surge_merge.auto_update prepare --base-sha CURRENT_MAIN_COMMIT
```

`CURRENT_MAIN_COMMIT` 需替换为此次完整检出的 40 位提交 SHA；`work/fmz-auto-package` 必须不存在。失败不会覆盖旧候选包。只有带有同一轮 `prepare` 输出摘要的包能进入发布阶段。

复现某个已发布模块：按 `sources-fmz.json` 获取不可变来源，验证其 SHA-256/字节数，再运行 `python -m surge_merge optimize-base INPUT --policy fmz-policy.json --output work/reproduced.sgmodule --report work/reproduced-report.json`，与 `reports/fmz200-update.json` 中的输出哈希比较。

## 失败后的检查与恢复

先查看失败运行的安全摘要及原因码，再查看 `main` 的实际提交和 `reports/fmz200-update.json`。如果状态是 `publication_unconfirmed`，不能仅凭红色作业判定未发布：网络中断可能发生在分支更新已经成功之后。

对精确目标或冲突漂移，应取得新旧不可变来源，重新审查相关条目；确认后同时重建来源锁、策略、模块及报告，不要只改 hash 或移除门禁。需要回退时，应由维护者在同一个提交中恢复上一成功版本的六个发布文件，并重新跑完整校验。自动流程不会自行强制回退 `main`、撤销人工提交或修改仓库保护。

## 仍然存在的限制

自动检查不等于 Surge 实机验证，不执行广告请求，不证明正则表达式的匹配集合没有重叠，也不证明所有规则仍然有效。即使引用 URL 没变，远端脚本或资源内容仍可在此流程之外独立变化。工具不静默固定或重新分发这些依赖。

GitHub 定时运行可能排队、延迟或被取消；公共仓库长期无活动时定时任务可能被停用。以 Actions 实际记录为准，不承诺精确的分钟级交付。GitHub Actions 权限或仓库分支保护可能阻止发布；流程会失败并保留当前 `main`，不会绕过保护。失败记录位于 Actions；仓库所有者可按自己的 GitHub 通知设置接收失败提醒，流程不会额外发送站外消息。

## 官方依据

- [GitHub Actions 安全使用与最小权限](https://docs.github.com/en/actions/reference/security/secure-use)
- [GitHub Actions 事件与定时行为](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule)
- [GitHub 内置 token 与触发行为](https://docs.github.com/en/actions/how-tos/writing-workflows/choosing-when-your-workflow-runs/triggering-a-workflow)
- [Git 引用更新 API](https://docs.github.com/en/rest/git/refs#update-a-reference)
