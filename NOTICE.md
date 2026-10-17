# fmz200 单来源候选说明

本目录的模块仅派生于 fmz200/wool_scripts，不含本次 blackmatrix7、墨鱼来源的规则合并。

上游作者：fmz200（奶思）及原文件中注明的贡献者。
上游地址：https://github.com/fmz200/wool_scripts/blob/3ca7487b4e4b86d9af76e50df72c62eacfbb659e/Surge/module/blockAds.module
原文件 SHA-256：d75a30e3410fccc4269c2749cdc430f2c6ef5b092bca1bc342279642f9918423
本次修改日期：2026-10-17
修改者：Xuemq（通过本仓库原创优化工具）
候选 SHA-256：4a58763b5b6a1043abf160d4fce59f14f2fff94bdb5f61cd693dd923744ec577

许可：该派生模块沿用上游 GNU GPL v3；完整上游许可位于 licenses/fmz200-GPL-3.0.txt。该说明不替其他来源重新授予许可。

修改：去除267条安全完全重复项，保留全部顺序型 Body/Header Rewrite；92个重复脚本标签改为确定性唯一名；恢复19个有上游证据的参数默认值；修复 Sparkle 与网易云脚本的旧式参数为具名 JSON 对象（7个原始行，对应5个最终脚本）；5个 JSON 响应采用等值 base64 表示。保留43组原有同键不同操作/正文及其顺序，不私自选取其中一条。另按明确选择排除9条应用专用规则（Rule 1条、URL Rewrite 4条、Map Local 4条）；它们是范围选择，不属于已证实失效规则。除这9条外，其余活动规则及顺序、MITM、脚本和原有修复全部保持不变。模块显示名改为“去广告优化 · fmz200”，说明准确标明单来源优化与实机验证限制；原作者与原始元信息保留。详见 fmz200-scope-diff.json。

脚本和资源仍引用原上游 URL，没有将脚本正文打包。远程依赖将来可能变化；模块字节可重现不代表外部依赖行为永远不变。本次只读检查全部110个去重外部依赖（fmz来源83个）均为HTTP 200、非空、非HTML；2个JSON资源解析通过。没有确认失效的依赖，因此未据此删除规则。链接可读取不等于广告匹配仍有效；也没有仅凭超时、403、规则年龄或域名推测删除规则。

jq Body Rewrite 要求 Surge iOS 5.14+；外部脚本可能另有版本要求。

仅完成静态解析、缺失参数检查、标签唯一性检查、默认参数 JSON 检查和合成测试。尚未在 Surge iOS 实机运行，也未证明不同正则没有重叠。建议在现有配置可恢复的前提下单独启用此模块测试，避免与原 fmz 模块同时启用而重复处理。

重现：使用仓库内 sources.json 的 fmz200 锁定来源、fmz-policy.json，以及 python -m surge_merge optimize-base 命令。详细逐行变更报告由该命令生成。

网易云首页开关采用 Keywos 官方 Surge 默认；标签页保留 fmz/Loon 预设 MY=true、DT=false、FX=true，只修复参数形状。这些是通用来源默认值，不是用户个人应用清单或偏好。
