# Crescentln Ruleset (OpenClash + Surge)

自建、可控、可自动更新的规则仓库，面向 OpenClash 和 Surge。

## 仓库与基础地址

- 仓库: [https://github.com/crescentln/new-project](https://github.com/crescentln/new-project)
- Raw Base: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist`

## 最简用法（单 URL，可直接复制）

你如果只想维护最少类别，优先用这 3 条：

### OpenClash（YAML）

- `REJECT`：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/reject.yaml`
- `DIRECT`：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/direct.yaml`
- `PROXY`：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/proxy.yaml`

### Surge（LIST）

- `REJECT`：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/reject.list`
- `DIRECT`：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/direct.list`
- `PROXY`：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/proxy.list`

建议顺序（从上到下）：`reject -> direct -> proxy`

## 你要求的高覆盖补充集合

- `gfw`（高覆盖代理补充）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/gfw.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/gfw.list`
- `global`（高覆盖全球集合）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/global.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/global.list`
- `tld_proxy`（IANA TLD 高覆盖代理集合）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/tld_proxy.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/tld_proxy.list`

当前构建计数（2026-02-20 本地构建）：

- `reject`: 175191
- `direct`: 18883
- `proxy`: 23648
- `gfw`: 109
- `global`: 23648
- `tld_proxy`: 1433

## 合并规则说明（你要求的重点）

### `reject`（动作：`REJECT`）

已合并以下内容到同一个规则集：

- EasyList: `https://easylist.to/easylist/easylist.txt`
- EasyPrivacy: `https://easylist.to/easylist/easyprivacy.txt`
- AdGuard DNS Filter: `https://filters.adtidy.org/dns/filter_1.txt`
- 本地可控补充：
  - `ruleset/manual/categories/reject.txt`
  - `ruleset/manual/categories/reject_extra.txt`
  - `ruleset/manual/categories/reject_drop.txt`
  - `ruleset/manual/categories/reject_no_drop.txt`

说明：原先 `reject_extra/reject_drop/reject_no_drop` 已合并，不再需要分别引用。

### `direct`（动作：`DIRECT`）

已合并以下直连来源：

- IANA IPv4/IPv6 Special Registry（官方）
- APNIC CN CIDR（官方）
- Cloudflare / AWS / GCP 官方 IP 段
- v2fly `geolocation-cn`
- 本地可控补充（`ruleset/manual/categories/direct.txt` + 直连相关手动文件）

### `proxy`（动作：`PROXY`）

已合并以下代理来源：

- v2fly `geolocation-!cn`
- 本地可控补充：`ruleset/manual/categories/proxy.txt`

## 权威来源清单（大源）

- IANA: [https://www.iana.org/](https://www.iana.org/)
- APNIC: [https://ftp.apnic.net/stats/apnic/delegated-apnic-latest](https://ftp.apnic.net/stats/apnic/delegated-apnic-latest)
- Cloudflare IPs: [https://www.cloudflare.com/ips/](https://www.cloudflare.com/ips/)
- AWS IP Ranges: [https://ip-ranges.amazonaws.com/ip-ranges.json](https://ip-ranges.amazonaws.com/ip-ranges.json)
- GCP IP Ranges: [https://www.gstatic.com/ipranges/cloud.json](https://www.gstatic.com/ipranges/cloud.json)
- IANA TLD: [https://data.iana.org/TLD/tlds-alpha-by-domain.txt](https://data.iana.org/TLD/tlds-alpha-by-domain.txt)
- v2fly/domain-list-community: [https://github.com/v2fly/domain-list-community](https://github.com/v2fly/domain-list-community)

## `ip / non_ip / domainset` 是什么

- `classical`（`openclash/<cat>.yaml`、`surge/<cat>.list`）：同时含域名规则和 IP 规则，最适合你要的“单 URL”。
- `non_ip`：只含域名类规则。
- `ip`：只含 CIDR/IP 类规则。
- `domainset`：纯域名后缀集合（部分客户端场景可用）。

## 自动更新

工作流：`.github/workflows/ruleset-update.yml`

- 每周自动运行一次：`cron: 17 3 * * 1`（UTC 周一 03:17）
- 规则有变化才自动提交 `ruleset/dist`

## 其他文档

- 全量分类与动作: `ruleset/dist/rule_catalog.md`
- 策略映射: `ruleset/dist/policy_reference.md`
- 构建与配置说明: `ruleset/README.md`
- 旧名称迁移: `ruleset/MAPPING.md`
