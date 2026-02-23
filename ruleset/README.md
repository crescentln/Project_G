# Self-Owned Ruleset Pipeline

这个目录负责从权威源/社区源拉取数据，构建 OpenClash + Surge 双栈规则。

## 设计目标

- 不依赖 Sukka/Quixotic 的产物地址。
- 所有来源、分类、动作都在本仓库可控。
- 同时输出 OpenClash 与 Surge 可直接引用格式。

## 配置入口

- 来源配置：`ruleset/config/sources.json`
- 动作映射：`ruleset/config/policy_map.json`
- 最小条目闸门：`ruleset/config/min_rules.json`（含硬阈值 `minimum_rule_counts` 与告警阈值 `warning_rule_counts`）
- 手工补充：`ruleset/manual/categories/*.txt`
- 手工排除：`ruleset/manual/exclude/*.txt`
- 手工放行：`ruleset/manual/allow/*.txt`（用于 reject* 降误杀）
- 冲突豁免：
  - 分类级：`ignore_conflicts`
  - 规则级：`ignore_conflicts_by_rule`（精确到 rule + categories）

## 分类策略

- 分别合并：`reject`（REJECT）与 `direct`（DIRECT），两者互不合并
- `reject_extra` / `reject_drop` / `reject_no_drop` 独立维护（可选挂载）
- 保持颗粒度：其余所有分类（如 `github`、`ai`、`vowifi`、`socialmedia`、`ecommerce`、`stream`、`stream_global`、`youtube`、`spotify`、`twitch`、`gfw`、`global`、`tld_proxy` 等）

`reject_*` 当前默认基线：

- `reject_extra`：更严格的广告/追踪补充
- `reject_drop`：高风险回连域名，静默丢弃
- `reject_no_drop`：广告域名显式拒绝（减少超时等待）

## 直连分类（重点标记）

除 `direct` 之外，以下分类也固定建议 `DIRECT`：

- `lan`
- `domestic`
- `cncidr`
- `apple_cn`
- `apple_cdn`
- `microsoft_cdn`
- `socialmedia_cn`
- `games_cn`
- `douyin`
- `dmca`
- `cdn`
- `download`

## 输出结构

产物目录：`ruleset/dist/`

- OpenClash：`openclash/<category>.yaml`
- Surge：`surge/<category>.list`
- 细分格式：`openclash/non_ip|ip`、`surge/non_ip|ip`、`*/domainset`
- 兼容路径：`compat/Clash/*`、`compat/List/*`
- 元数据：`index.json`、`policy_reference.md`、`rule_catalog.md`、`meta/*.json`
- 一键复制：`url_catalog.md`（每个分类的 OpenClash/Surge 单 URL）
- 来源审计：`source_authority.md`（official/community/owner 来源矩阵）
- 冲突报告：`conflicts.json`（含 `cross_action/high/medium/low` 统计）
- 抓取报告：`fetch_report.json`（含 `fallback_cache_count`）
- 推荐顺序模板：`recommended_openclash.yaml`、`recommended_surge.conf`
- 发布记录：`CHANGELOG.md`
- 可直接粘贴模板：
  - `ruleset/examples/openclash-rules.yaml`
  - `ruleset/examples/surge-rules.conf`
  - `ruleset/examples/openclash-rules-granular.yaml`
  - `ruleset/examples/surge-rules-granular.conf`

## 构建与校验

```bash
python3 ruleset/scripts/build_rulesets.py
python3 ruleset/scripts/generate_recommended_templates.py
python3 ruleset/scripts/generate_reference_indexes.py \
  --index ruleset/dist/index.json \
  --raw-base-url "https://raw.githubusercontent.com/<owner>/<repo>/main/ruleset/dist" \
  --urls-out ruleset/dist/url_catalog.md \
  --sources-out ruleset/dist/source_authority.md
python3 ruleset/scripts/validate_rulesets.py
python3 ruleset/scripts/check_smoke_probes.py
python3 ruleset/scripts/check_allowlist_effective.py
python3 ruleset/scripts/check_quality_gates.py \
  --current ruleset/dist/policy_reference.json \
  --fetch-report ruleset/dist/fetch_report.json \
  --conflicts ruleset/dist/conflicts.json \
  --minimums ruleset/config/min_rules.json
```

离线（使用缓存）：

```bash
python3 ruleset/scripts/build_rulesets.py --offline
```

## 自动更新

工作流：`.github/workflows/ruleset-update.yml`

- 每周执行：`17 3 * * 1`（UTC）
- 先执行冲突与质量闸门（含关键分类最小条目阈值），再在 `ruleset/dist` 变化时提交
- 自动写入 `ruleset/dist/CHANGELOG.md`，并打 `ruleset-YYYYMMDDTHHMMSSZ` 回滚标签
- 有变化时自动创建 GitHub Release，说明由脚本生成（`CHANGELOG` + 质量指标）

## 当前主要数据源

- 官方：IANA、APNIC、Cloudflare、AWS、GCP、IANA TLD
- 社区高质量：v2fly/domain-list-community
- 本地可控：`ruleset/manual/categories/*.txt`（包含 `github`、`vowifi`、`stream` 与自定义 reject/direct 增补）
