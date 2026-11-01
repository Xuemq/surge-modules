# fmz200 单来源优化说明

此模块仅派生于 fmz200/wool_scripts，不含 blackmatrix7 或墨鱼规则合并。
上游作者：fmz200（奶思）及原文件中注明的贡献者；模块内保留原作者信息。
上游固定版本：https://raw.githubusercontent.com/fmz200/wool_scripts/4b7830670baf235ed945085cb926dc499cf619e0/Surge/module/blockAds.module
原文件 SHA-256：cc306fc3e061d106d5197a5a1be42f940193c32bc7234302ff31b357f4a01076
本次修改日期：2026-11-01
修改者：Xuemq（通过本仓库原创优化工具）
模块 SHA-256：2af311aad24da8db2233947fd21419c189d3310e74ae8bc7237899a962b7a884

许可：沿用上游 GNU GPL v3；完整许可见 licenses/fmz200-GPL-3.0.txt。
修改：安全完全重复项去重 167 条；重复脚本标签确定性改名 49 项；具名 JSON 参数修复 5 行；JSON 等值 base64 修复 5 行；恢复有证据的缺失参数默认值；保留原有不同操作与顺序。
明确选择的范围排除：768 条，均绑定原始段名和行哈希，不代表它们已经失效。自动更新仅允许精确目标移动行号，不能扩大删除范围或自动改写决定。完整逐行报告见 reports/fmz200-build-report.json；首次范围精简的历史对比见 reports/fmz200-scope-diff.json（不代表后续版本差异）。
明确保留的旧基线规则：1 条，绑定已审历史定义与唯一当前源锚点。上游重新引入同键规则或锚点改变会阻断更新，不会自动删除这项保护。

每周维护或手动运行通过后，发布至同一个 modules/fmz200.optimized.sgmodule 地址。任何校验、下载、测试或发布门禁失败时保留最后成功版本。自动发布记录见 reports/fmz200-update.json；复现使用 sources-fmz.json 和 fmz-policy.json。

引用脚本和资源仍使用上游 URL，不打包或执行其正文。相同 URL 的远端内容仍可能独立变化；模块可复现不保证远端依赖不变。不会仅凭超时、403、年龄或域名猜测删除规则。
仅完成静态检查与合成测试，尚未在 Surge iOS 实机运行，也没有正则匹配集合重叠或广告有效性证明。jq Body Rewrite 要求 Surge iOS 5.14+；远程脚本可能有更高要求。详细门禁和限制见 docs/auto-updates.md。
