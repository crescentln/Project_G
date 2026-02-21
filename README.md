# Crescentln Ruleset (OpenClash + Surge)

自建、可控、可自动更新的规则仓库，面向 OpenClash 和 Surge。

## 仓库与基础地址

- 仓库: [https://github.com/crescentln/new-project](https://github.com/crescentln/new-project)
- Raw Base: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist`

## 你的当前策略（已按你要求）

- `reject` 和 `direct` 分别各自合并，互不合并
- 其余分类保持颗粒度（`ai/telegram/stream_*/google/...` 等继续独立）

## 最常用可复制 URL

### OpenClash

- 合并拦截 `reject`（REJECT）：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/reject.yaml`
- 合并直连 `direct`（DIRECT）：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/direct.yaml`

### Surge

- 合并拦截 `reject`（REJECT）：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/reject.list`
- 合并直连 `direct`（DIRECT）：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/direct.list`

## 直接可用配置模板

- OpenClash 模板（`rule-providers + rules`）：
  - `ruleset/examples/openclash-rules.yaml`
  - `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/examples/openclash-rules.yaml`
- Surge 模板（`[Rule]`）：
  - `ruleset/examples/surge-rules.conf`
  - `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/examples/surge-rules.conf`

说明：

- 这两份模板已按当前 `policy_map` 生成，包含全部分类 URL。
- 如果你的策略组名称不是 `PROXY`，把模板里结尾策略 `PROXY` 改成你的组名。

## 高覆盖补充（保持颗粒度）

- `gfw`
  - OpenClash: `.../openclash/gfw.yaml`
  - Surge: `.../surge/gfw.list`
- `global`
  - OpenClash: `.../openclash/global.yaml`
  - Surge: `.../surge/global.list`
- `tld_proxy`
  - OpenClash: `.../openclash/tld_proxy.yaml`
  - Surge: `.../surge/tld_proxy.list`

## 两个合并规则的来源

### `reject`（REJECT）

- EasyList
- EasyPrivacy
- AdGuard DNS Filter
- 本地可控补充：
  - `ruleset/manual/categories/reject.txt`
  - `ruleset/manual/categories/reject_extra.txt`
  - `ruleset/manual/categories/reject_drop.txt`
  - `ruleset/manual/categories/reject_no_drop.txt`

### `direct`（DIRECT）

- IANA IPv4/IPv6 Special Registry
- APNIC CN CIDR
- Cloudflare / AWS / GCP 官方 IP 段
- v2fly `geolocation-cn`
- 本地可控补充（`ruleset/manual/categories/direct.txt` 及直连相关手工集合）

## 权威来源（大源）

- IANA: [https://www.iana.org/](https://www.iana.org/)
- APNIC: [https://ftp.apnic.net/stats/apnic/delegated-apnic-latest](https://ftp.apnic.net/stats/apnic/delegated-apnic-latest)
- Cloudflare IPs: [https://www.cloudflare.com/ips/](https://www.cloudflare.com/ips/)
- AWS IP Ranges: [https://ip-ranges.amazonaws.com/ip-ranges.json](https://ip-ranges.amazonaws.com/ip-ranges.json)
- GCP IP Ranges: [https://www.gstatic.com/ipranges/cloud.json](https://www.gstatic.com/ipranges/cloud.json)
- IANA TLD: [https://data.iana.org/TLD/tlds-alpha-by-domain.txt](https://data.iana.org/TLD/tlds-alpha-by-domain.txt)
- v2fly/domain-list-community: [https://github.com/v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)

## `ip / non_ip / domainset` 说明

- 你想要“单 URL”时，优先用：`openclash/<cat>.yaml`、`surge/<cat>.list`
- `non_ip`：仅域名规则
- `ip`：仅 CIDR/IP 规则
- `domainset`：纯域名集合

## 自动更新

工作流：`.github/workflows/ruleset-update.yml`

- 每周自动运行：`cron: 17 3 * * 1`（UTC）
- 仅 `ruleset/dist` 变化时自动提交

## 其他文档

- 全量分类与动作: `ruleset/dist/rule_catalog.md`
- 策略映射: `ruleset/dist/policy_reference.md`
- 构建与配置说明: `ruleset/README.md`
- 旧名称迁移: `ruleset/MAPPING.md`
