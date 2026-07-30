# Ruleset Pipeline (Public Snapshot)

此目录在公开仓库中仅保留构建脚本与发布产物所需配置。

## 可见性说明

- 详细设计与运维说明已迁移到私有文档仓库，仅仓库所有者可见。
- 公开仓库仅用于发布 OpenClash / Surge / Stash 可抓取规则文件。
- 私有说明仓库：`crescentln/Project_G_PrivateDocs`（private）。

## 公开产物目录

- `dist/openclash/`: OpenClash YAML 主入口与拆分产物
- `dist/surge/`: Surge list 主入口与拆分产物
- `dist/stash/`: Stash classical 主入口，以及 `domainset` / `ipcidr` / `classical` 拆分产物
- `dist/recommended_stash.yaml`: Stash classical 兼容推荐模板
- `dist/recommended_stash_native.yaml`: Stash Native 优化推荐模板（优先使用 `domainset` / `ipcidr`，仅保留 residual classical）
- `dist/openclash/wechat.yaml`: 微信核心、媒体与服务 DNS 的窄范围直连规则；必须位于拒绝类规则之前
- `dist/sources.lock.json`: 本轮构建采用的不可变上游提交
- `dist/source_provenance.json`: 来源、内容摘要、解析统计与 include 图
- `dist/source_health.json`: 来源新鲜度、镜像与缓存状态
- `dist/rule_delta.json`: 逐规则新增/删除、来源归因与风险标记
- `dist/client_parity.json`: OpenClash / Surge / Stash 的实际有效规则数及丢失类型
- `dist/candidate_sources.json`: 只读上游雷达结果；不会直接并入发布规则

## 质量门禁

- 单元与配置一致性测试：`python3 -m unittest discover -s ruleset/tests -v`
- 高频 Source Discovery 只生成候选产物，不写入 `main`、tag 或 Release。
- 低风险候选必须连续两轮语义摘要一致才可自动晋升；高风险候选必须通过受保护环境复核。
- 发布只消费已验证的候选归档，不重新抓取或重新构建，并附带 GitHub artifact attestation。
- 每类规则使用独立的增删、比例、apex、regex、CIDR 与跨动作重叠预算。
