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

## 质量门禁

- 单元与配置一致性测试：`python3 -m unittest discover -s ruleset/tests -v`
- 发布构建分为只读构建验证与最小写权限发布两个作业。
- 大幅规则数量变化只能通过绑定旧基线 SHA-256、类别和新数量区间的一次性批准。
