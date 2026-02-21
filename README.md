# Crescentln Ruleset (OpenClash + Surge)

自建、可控、可自动更新的规则仓库，面向 OpenClash 和 Surge。

## 仓库与基础地址

- 仓库: [https://github.com/crescentln/new-project](https://github.com/crescentln/new-project)
- Raw Base: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist`

## 你的当前策略（已按你要求）

- `reject` 和 `direct` 分别各自合并，互不合并
- `reject_extra` / `reject_drop` / `reject_no_drop` 保持独立可选
- 其余分类保持颗粒度（`ai/telegram/stream_*/google/...` 等继续独立）

## 直连规则标记（DIRECT）

下面这些是“应直连”的分类（除了 `direct` 本身）：

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

## 最常用可复制 URL

### OpenClash

- 合并拦截 `reject`（REJECT）：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/reject.yaml`
- 合并直连 `direct`（DIRECT）：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/direct.yaml`

### Surge

- 合并拦截 `reject`（REJECT）：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/reject.list`
- 合并直连 `direct`（DIRECT）：`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/direct.list`

## 你点名要的独立规则 URL（OpenClash + Surge）

- `github`
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/github.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/github.list`
- `ai`
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/ai.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/ai.list`
- `vowifi`
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/vowifi.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/vowifi.list`
- `socialmedia`（国外社交媒体）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/socialmedia.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/socialmedia.list`
- `ecommerce`（国外购物）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/ecommerce.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/ecommerce.list`
- `stream_global`（国外流媒体高覆盖）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/stream_global.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/stream_global.list`
- `spotify`
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/spotify.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/spotify.list`
- `youtube`
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/youtube.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/youtube.list`
- `twitch`
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/twitch.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/twitch.list`
- `reject`（主拦截）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/reject.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/reject.list`
- `direct`（主直连）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/direct.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/direct.list`
- `reject_extra`（可选补充拦截）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/reject_extra.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/reject_extra.list`
- `reject_drop`（可选静默丢弃）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/reject_drop.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/reject_drop.list`
- `reject_no_drop`（可选显式拒绝）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/openclash/reject_no_drop.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist/surge/reject_no_drop.list`

说明：`reject_extra` / `reject_drop` / `reject_no_drop` 默认是“你可控的自定义空位”，只有你在 `ruleset/manual/categories/*.txt` 填了内容才会生效。

## 你点名分类的数据来源（权威/主流）

- `github`: v2fly `github` + `gitlab` + `gitee`，外加本地可控补充
- `ai`: v2fly `openai`、`anthropic`、`perplexity`、`google-gemini`、`github-copilot`
- `stream_global`: v2fly `netflix`、`hulu`、`disney`、`abema`、`apple-tvplus`、`primevideo`
- `socialmedia`: v2fly `facebook`、`instagram`、`twitter`、`discord`、`reddit`、`quora`、`medium`
- `ecommerce`: v2fly `category-ecommerce`
- `spotify` / `youtube` / `twitch`: v2fly 对应官方维护集合
- `vowifi`: 3GPP `pub.3gppnetwork.org` 命名体系 + 你可控的运营商 ePDG 增补

## 直接可用配置模板

- OpenClash 模板（`rule-providers + rules`）：
  - `ruleset/examples/openclash-rules.yaml`
  - `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/examples/openclash-rules.yaml`
- Surge 模板（`[Rule]`）：
  - `ruleset/examples/surge-rules.conf`
  - `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/examples/surge-rules.conf`
- OpenClash 细颗粒度模板（每个代理分类独立策略组）：
  - `ruleset/examples/openclash-rules-granular.yaml`
  - `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/examples/openclash-rules-granular.yaml`
- Surge 细颗粒度模板（每个代理分类独立策略组）：
  - `ruleset/examples/surge-rules-granular.conf`
  - `https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/examples/surge-rules-granular.conf`

说明：

- 这两份模板已按当前 `policy_map` 生成，包含全部分类 URL。
- 如果你的策略组名称不是 `PROXY`，把模板里结尾策略 `PROXY` 改成你的组名。
- 细颗粒度模板里使用内容分类名策略组：如 `PROXY_AI`、`PROXY_APPLE_SERVICES`、`PROXY_MICROSOFT`、`PROXY_YOUTUBE`。

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
- `stream_global`
  - OpenClash: `.../openclash/stream_global.yaml`
  - Surge: `.../surge/stream_global.list`

## 两个合并规则的来源

### `reject`（REJECT）

- EasyList
- EasyPrivacy
- AdGuard DNS Filter
- 本地可控补充：`ruleset/manual/categories/reject.txt`

### 独立可选拦截集合

- `reject_extra`（REJECT）：`ruleset/manual/categories/reject_extra.txt`
- `reject_drop`（REJECT-DROP）：`ruleset/manual/categories/reject_drop.txt`
- `reject_no_drop`（REJECT-NO-DROP）：`ruleset/manual/categories/reject_no_drop.txt`

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
