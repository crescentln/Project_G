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

## 关键分类（简化部署）

- `reject` -> `REJECT`（合并拒绝类）
- `direct` -> `DIRECT`（合并直连类）
- `proxy` -> `PROXY`（合并代理类）

高覆盖补充：`gfw` / `global` / `tld_proxy`。

## 输出结构

产物目录：`ruleset/dist/`

- OpenClash：`openclash/<category>.yaml`
- Surge：`surge/<category>.list`
- 细分格式：`openclash/non_ip|ip`、`surge/non_ip|ip`、`*/domainset`
- 兼容路径：`compat/Clash/*`、`compat/List/*`
- 元数据：`index.json`、`policy_reference.md`、`rule_catalog.md`、`meta/*.json`

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
- 本地可控：`ruleset/manual/categories/*.txt`
