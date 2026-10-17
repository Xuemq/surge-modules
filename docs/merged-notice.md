# 三源合并模块：来源、修改和使用限制

模块：`modules/merged.optimized.sgmodule`；名称：去广告合并优化 · 三源。

以 fmz200 为基底，补充 blackmatrix7 与墨鱼，修改日期为 2026-10-17，整合者为 Xuemq。原作者和贡献者保留各自权利。来源和 SHA-256 锁定在 `sources-merged.json`；逐项转换、范围和冲突决定在 `merged-policy.json`，构建结果在 `reports/merged-build-report.json`。

## 原始来源与许可材料

- fmz200（奶思）及原文件贡献者：[wool_scripts](https://github.com/fmz200/wool_scripts/blob/3ca7487b4e4b86d9af76e50df72c62eacfbb659e/Surge/module/blockAds.module)。原仓库 GPL v3 全文原样保存在 `licenses/fmz200-GPL-3.0.txt`。
- blackmatrix7 及原文件贡献者：[AllInOne](https://github.com/blackmatrix7/ios_rule_script/blob/a75313d36b049b8aca5b26beffafb1b0ec8c564d/rewrite/Surge/AllInOne/AllInOne.sgmodule)。原仓库 GPL v2 全文原样保存在 `licenses/blackmatrix7-GPL-2.0.txt`；同一提交的根 README 和 AllInOne README 原样保存在 `notices/blackmatrix7-README.md`、`notices/blackmatrix7-AllInOne-README.md`。
- ddgksf2013（墨鱼）及源文件列出的 @blackmatrix7、@app2smile、@DivineEngine、@kyle、@Nick-workflow、@kkpp、@LE：[StartUpAds.conf](https://ddgksf2013.top/rewrite/StartUpAds.conf)。原始头部保存在 `notices/moyu-original-header.txt`，其中注明“如需引用请注明出处，谢谢合作！”。该可变来源的精确输入快照保存在 `upstream/moyu.source`。
- 三份源文件的全部注释和元信息原文保存在 `notices/*-source-comments.txt`；模块头部也保留原始来源头部。外部脚本/资源继续引用各自上游，未把其正文打包为本仓库作品。

没有声明整个合成模块统一适用 GPL-3.0，也没有声明获得了新的作者授权或跨许可证兼容性确认。blackmatrix7 的 README 另有仅学习研究、24小时内删除、限制宣传/转载等条件；这些条件与同仓库 GPL 文本的关系未在此作法律结论。墨鱼头部署名要求不等于已经确认完整的修改、再分发或再许可授权。保留上述原文和链接不改变其效力。

## 本次技术修改

- fmz 单源阶段保留已核对的去重、脚本唯一命名、参数修复以及9条范围排除。
- 墨鱼 QX 指令转换为原生 Surge 表达；仅排除已指定的 TestFlight 地区修改。两条原脚本在 Surge 下无实际效果的状态修改，使用本仓库原创 `scripts/header-status.js` 适配，保留原有请求匹配和请求头条件（在响应阶段执行）。
- 冲突采用基线优先，并保留所有基线同组条目的原始顺序。补充源冲突优先保留原来的成功响应格式或定点正文修改，不把它们当成与 reject 等价。
- 按具体静态见证排除166条可能覆盖基线行为的补充项；原先排除的应用专用匹配不会通过另两源重新引入。整个补充条目被移除，其超出见证范围的额外覆盖也随之放弃。
- 173对有限正则见证重放通过；保留一个经核对的幂等常量替换例外。该检查不能证明其他正则永不重叠。

这份模块通过静态解析、确定性重建和合成测试，尚未在 Surge 或有关应用内实机验证。需要 Surge iOS 5.14+ 的 jq 支持，外部脚本可能有更高版本要求。远程依赖可能独立变化；链接可读不证明广告规则持续有效。

新订阅地址为 `https://raw.githubusercontent.com/Xuemq/surge-modules/main/modules/merged.optimized.sgmodule`。原 `modules/fmz200.optimized.sgmodule` 保留为单源回退。请勿同时启用二者或原始三份去广告模块，以免重复处理；安装前保存可恢复配置，实机异常时停用新模块并回退。

## 重现

使用 Python 3.11+，从 `sources-merged.json` 的两条不可变 URL 取得 fmz200、blackmatrix7 输入，按清单校验字节数和 SHA-256，分别放入 `.cache/fmz200.source`、`.cache/blackmatrix7.source`。将 `upstream/moyu.source` 复制到 `.cache/moyu.source` 并校验同一清单。然后执行：

`python3 -m surge_merge.combined --bundle merged-policy.json --cache .cache --output-dir work/merged-release`

构建器不联网，不执行上游脚本，不自行增加冲突决策。来源或已审目标漂移时失败，不覆盖最后正常版本。
