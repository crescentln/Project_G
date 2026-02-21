# Self-Owned Ruleset Pipeline

这个目录负责从权威源/社区源拉取数据，构建 OpenClash + Surge 双栈规则。

## 设计目标

- 不依赖 Sukka/Quixotic 的产物地址。
- 所有来源、分类、动作都在本仓库可控。
- 同时输出 OpenClash 与 Surge 可直接引用格式。

## 配置入口

- 来源配置：`ruleset/config/sources.json`
- 动作映射：`ruleset/config/policy_map.json`
- 手工补充：`ruleset/manual/categories/*.txt`
- 手工排除：`ruleset/manual/exclude/*.txt`

## 分类策略（按你的要求）

- 分别合并：`reject`（REJECT）与 `direct`（DIRECT），两者互不合并
- `reject_extra` / `reject_drop` / `reject_no_drop` 独立维护（可选挂载）
- 保持颗粒度：其余所有分类（如 `github`、`ai`、`vowifi`、`socialmedia`、`ecommerce`、`stream_global`、`youtube`、`spotify`、`twitch`、`gfw`、`global`、`tld_proxy` 等）

## 输出结构

产物目录：`ruleset/dist/`

- OpenClash：`openclash/<category>.yaml`
- Surge：`surge/<category>.list`
- 细分格式：`openclash/non_ip|ip`、`surge/non_ip|ip`、`*/domainset`
- 兼容路径：`compat/Clash/*`、`compat/List/*`
- 元数据：`index.json`、`policy_reference.md`、`rule_catalog.md`、`meta/*.json`
- 可直接粘贴模板：
  - `ruleset/examples/openclash-rules.yaml`
  - `ruleset/examples/surge-rules.conf`
  - `ruleset/examples/openclash-rules-granular.yaml`
  - `ruleset/examples/surge-rules-granular.conf`

## 构建与校验

```bash
python3 ruleset/scripts/build_rulesets.py
python3 ruleset/scripts/validate_rulesets.py
```

离线（使用缓存）：

```bash
python3 ruleset/scripts/build_rulesets.py --offline
```

## 自动更新

工作流：`.github/workflows/ruleset-update.yml`

- 每周执行：`17 3 * * 1`（UTC）
- 仅当 `ruleset/dist` 变化时提交

## 当前主要数据源

- 官方：IANA、APNIC、Cloudflare、AWS、GCP、IANA TLD
- 社区高质量：v2fly/domain-list-community
- 本地可控：`ruleset/manual/categories/*.txt`（包含 `github`、`vowifi`、`stream_global` 与自定义 reject/direct 增补）
