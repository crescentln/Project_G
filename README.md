# Crescentln Ruleset (OpenClash + Surge)

自建、可控、可自动更新的规则仓库，面向 OpenClash 和 Surge。

## 仓库与基础地址

- 仓库: [https://github.com/crescentln/Project_G](https://github.com/crescentln/Project_G)
- Raw Base: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist`

## 当前策略

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

- 合并拦截 `reject`（REJECT）：`https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/reject.yaml`
- 合并直连 `direct`（DIRECT）：`https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/direct.yaml`

### Surge

- 合并拦截 `reject`（REJECT）：`https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/reject.list`
- 合并直连 `direct`（DIRECT）：`https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/direct.list`

## 常用独立规则 URL（OpenClash + Surge）

- `github`
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/github.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/github.list`
- `ai`
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/ai.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/ai.list`
- `vowifi`
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/vowifi.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/vowifi.list`
- `socialmedia`（国外社交媒体）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/socialmedia.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/socialmedia.list`
- `anime`（海外动漫/漫画/成人站）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/anime.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/anime.list`
- `ecommerce`（国外购物）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/ecommerce.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/ecommerce.list`
- `games`（国际游戏平台）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/games.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/games.list`
- `stream`（整合流媒体，推荐）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/stream.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/stream.list`
- `stream_global`（国外流媒体高覆盖）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/stream_global.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/stream_global.list`
- `spotify`
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/spotify.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/spotify.list`
- `youtube`
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/youtube.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/youtube.list`
- `twitch`
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/twitch.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/twitch.list`
- `reject`（主拦截）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/reject.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/reject.list`
- `direct`（主直连）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/direct.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/direct.list`
- `reject_extra`（可选补充拦截）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/reject_extra.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/reject_extra.list`
- `reject_drop`（可选静默丢弃）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/reject_drop.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/reject_drop.list`
- `reject_no_drop`（可选显式拒绝）
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/reject_no_drop.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/reject_no_drop.list`

说明：`reject_extra` / `reject_drop` / `reject_no_drop` 默认是“仓库可控的自定义空位”，仅在 `ruleset/manual/categories/*.txt` 添加内容时生效。
若出现误杀，可在 `ruleset/manual/allow/reject*.txt` 放行域名（构建时会从对应 reject 集合移除）。

## 主要分类的数据来源（权威/主流）

- `github`: v2fly `github` + `gitlab` + `gitee` + `codeberg` + `sourcehut`，外加本地可控补充
- `ai`: v2fly `category-ai-!cn` + `openai`、`anthropic`、`perplexity`、`google-gemini`、`github-copilot`
- `stream`（整合流媒体）: v2fly `netflix`、`hulu`、`disney`、`hbo`、`discoveryplus`、`plutotv`、`roku`、`tubi`、`sling`、`showtimeanytime`、`nbcuniversal`、`abema`、`apple-tvplus`、`primevideo`、`mytvsuper`、`viu`、`now`、`bahamut`、`hamivideo`、`catchplay`、`litv`（已包含 Netflix）
- `stream_us`: v2fly `netflix`、`hulu`、`disney` + `hbo`、`discoveryplus`、`plutotv`、`roku`、`tubi`、`sling`、`showtimeanytime`、`nbcuniversal`（可选细分）
- `stream_global`: v2fly `netflix`、`hulu`、`disney`、`abema`、`apple-tvplus`、`primevideo`
- `socialmedia`: v2fly `category-social-media-!cn` + `facebook`、`instagram`、`twitter`、`discord`、`reddit`、`quora`、`medium`
- `anime`: 仓库可控集合（海外动漫/漫画/成人站点，含 `pornhub`、`91porn` 等）
- `socialmedia_cn`: v2fly `category-social-media-cn` + `sina` + `zhihu` + `bilibili` + 本地可控补充
- `ecommerce`: v2fly `category-ecommerce`
- `spotify` / `youtube` / `twitch`: v2fly 对应官方维护集合
- `apple_proxy`: v2fly `icloud`（排除 `@cn`）+ 本地可控补充
- `icloud_private_relay`: v2fly `icloudprivaterelay` + 本地可控补充，建议 `PROXY`
- `download`: v2fly `category-android-app-download` + 本地可控补充（非游戏平台）
- `games`: v2fly `category-games-!cn` + `steam`、`epicgames`、`blizzard`、`origin`、`nintendo`、`xbox`、`playstation`、`ubisoft` + 本地可控补充
- `vowifi`: 3GPP `pub.3gppnetwork.org` 命名体系 + 美国运营商优先（MCC 310~316）+ 仓库可控的 ePDG/IMS 增补

## 直接可用配置模板

- OpenClash 模板（`rule-providers + rules`）：
  - `ruleset/examples/openclash-rules.yaml`
  - `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/examples/openclash-rules.yaml`
- Surge 模板（`[Rule]`）：
  - `ruleset/examples/surge-rules.conf`
  - `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/examples/surge-rules.conf`
- OpenClash 细颗粒度模板（每个代理分类独立策略组）：
  - `ruleset/examples/openclash-rules-granular.yaml`
  - `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/examples/openclash-rules-granular.yaml`
- Surge 细颗粒度模板（每个代理分类独立策略组）：
  - `ruleset/examples/surge-rules-granular.conf`
  - `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/examples/surge-rules-granular.conf`
- 自动生成推荐顺序模板（每次构建更新）：
  - OpenClash: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/recommended_openclash.yaml`
  - Surge: `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/recommended_surge.conf`
- 自动生成全量 URL 清单（每个分类 OpenClash + Surge 单入口）：
  - `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/url_catalog.md`
- 自动生成来源权威矩阵（official/community/owner）：
  - `https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/source_authority.md`

说明：

- 这两份模板已按当前 `policy_map` 生成，包含全部分类 URL。
- 如果策略组名称不是 `PROXY`，将模板里的 `PROXY` 替换为实际策略组名称。
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
- `stream`（推荐整合）
  - OpenClash: `.../openclash/stream.yaml`
  - Surge: `.../surge/stream.list`

## 全量规则总表（OpenClash + Surge）

> 自动生成，按策略优先级排序。

| 规则 | 动作 | OpenClash | Surge |
|---|---|---|---|
| `reject` | 拦截 (REJECT) | [`openclash/reject.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/reject.yaml) | [`surge/reject.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/reject.list) |
| `reject_extra` | 拦截 (REJECT) | [`openclash/reject_extra.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/reject_extra.yaml) | [`surge/reject_extra.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/reject_extra.list) |
| `reject_drop` | 丢弃 (REJECT-DROP) | [`openclash/reject_drop.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/reject_drop.yaml) | [`surge/reject_drop.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/reject_drop.list) |
| `reject_no_drop` | 拒绝 (REJECT-NO-DROP) | [`openclash/reject_no_drop.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/reject_no_drop.yaml) | [`surge/reject_no_drop.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/reject_no_drop.list) |
| `httpdns` | 拦截 (REJECT) | [`openclash/httpdns.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/httpdns.yaml) | [`surge/httpdns.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/httpdns.list) |
| `lan` | 直连 (DIRECT) | [`openclash/lan.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/lan.yaml) | [`surge/lan.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/lan.list) |
| `direct` | 直连 (DIRECT) | [`openclash/direct.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/direct.yaml) | [`surge/direct.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/direct.list) |
| `domestic` | 直连 (DIRECT) | [`openclash/domestic.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/domestic.yaml) | [`surge/domestic.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/domestic.list) |
| `cncidr` | 直连 (DIRECT) | [`openclash/cncidr.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/cncidr.yaml) | [`surge/cncidr.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/cncidr.list) |
| `apple_cn` | 直连 (DIRECT) | [`openclash/apple_cn.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/apple_cn.yaml) | [`surge/apple_cn.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/apple_cn.list) |
| `apple_cdn` | 直连 (DIRECT) | [`openclash/apple_cdn.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/apple_cdn.yaml) | [`surge/apple_cdn.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/apple_cdn.list) |
| `microsoft_cdn` | 直连 (DIRECT) | [`openclash/microsoft_cdn.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/microsoft_cdn.yaml) | [`surge/microsoft_cdn.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/microsoft_cdn.list) |
| `socialmedia_cn` | 直连 (DIRECT) | [`openclash/socialmedia_cn.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/socialmedia_cn.yaml) | [`surge/socialmedia_cn.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/socialmedia_cn.list) |
| `games_cn` | 直连 (DIRECT) | [`openclash/games_cn.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/games_cn.yaml) | [`surge/games_cn.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/games_cn.list) |
| `douyin` | 直连 (DIRECT) | [`openclash/douyin.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/douyin.yaml) | [`surge/douyin.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/douyin.list) |
| `dmca` | 直连 (DIRECT) | [`openclash/dmca.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/dmca.yaml) | [`surge/dmca.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/dmca.list) |
| `cdn` | 直连 (DIRECT) | [`openclash/cdn.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/cdn.yaml) | [`surge/cdn.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/cdn.list) |
| `download` | 直连 (DIRECT) | [`openclash/download.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/download.yaml) | [`surge/download.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/download.list) |
| `telegram` | 代理 (PROXY) | [`openclash/telegram.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/telegram.yaml) | [`surge/telegram.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/telegram.list) |
| `stream` | 代理 (PROXY) | [`openclash/stream.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/stream.yaml) | [`surge/stream.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/stream.list) |
| `stream_us` | 代理 (PROXY) | [`openclash/stream_us.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/stream_us.yaml) | [`surge/stream_us.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/stream_us.list) |
| `stream_jp` | 代理 (PROXY) | [`openclash/stream_jp.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/stream_jp.yaml) | [`surge/stream_jp.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/stream_jp.list) |
| `stream_hk` | 代理 (PROXY) | [`openclash/stream_hk.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/stream_hk.yaml) | [`surge/stream_hk.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/stream_hk.list) |
| `stream_tw` | 代理 (PROXY) | [`openclash/stream_tw.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/stream_tw.yaml) | [`surge/stream_tw.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/stream_tw.list) |
| `stream_global` | 代理 (PROXY) | [`openclash/stream_global.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/stream_global.yaml) | [`surge/stream_global.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/stream_global.list) |
| `ai` | 代理 (PROXY) | [`openclash/ai.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/ai.yaml) | [`surge/ai.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/ai.list) |
| `apple_proxy` | 代理 (PROXY) | [`openclash/apple_proxy.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/apple_proxy.yaml) | [`surge/apple_proxy.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/apple_proxy.list) |
| `icloud_private_relay` | 代理 (PROXY) | [`openclash/icloud_private_relay.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/icloud_private_relay.yaml) | [`surge/icloud_private_relay.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/icloud_private_relay.list) |
| `apple_services` | 代理 (PROXY) | [`openclash/apple_services.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/apple_services.yaml) | [`surge/apple_services.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/apple_services.list) |
| `apple_intelligence` | 代理 (PROXY) | [`openclash/apple_intelligence.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/apple_intelligence.yaml) | [`surge/apple_intelligence.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/apple_intelligence.list) |
| `microsoft` | 代理 (PROXY) | [`openclash/microsoft.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/microsoft.yaml) | [`surge/microsoft.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/microsoft.list) |
| `github` | 代理 (PROXY) | [`openclash/github.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/github.yaml) | [`surge/github.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/github.list) |
| `games` | 代理 (PROXY) | [`openclash/games.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/games.yaml) | [`surge/games.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/games.list) |
| `youtube` | 代理 (PROXY) | [`openclash/youtube.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/youtube.yaml) | [`surge/youtube.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/youtube.list) |
| `abema` | 代理 (PROXY) | [`openclash/abema.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/abema.yaml) | [`surge/abema.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/abema.list) |
| `apple_tv` | 代理 (PROXY) | [`openclash/apple_tv.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/apple_tv.yaml) | [`surge/apple_tv.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/apple_tv.list) |
| `primevideo` | 代理 (PROXY) | [`openclash/primevideo.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/primevideo.yaml) | [`surge/primevideo.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/primevideo.list) |
| `spotify` | 代理 (PROXY) | [`openclash/spotify.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/spotify.yaml) | [`surge/spotify.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/spotify.list) |
| `twitch` | 代理 (PROXY) | [`openclash/twitch.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/twitch.yaml) | [`surge/twitch.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/twitch.list) |
| `google` | 代理 (PROXY) | [`openclash/google.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/google.yaml) | [`surge/google.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/google.list) |
| `googlefcm` | 代理 (PROXY) | [`openclash/googlefcm.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/googlefcm.yaml) | [`surge/googlefcm.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/googlefcm.list) |
| `paypal` | 代理 (PROXY) | [`openclash/paypal.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/paypal.yaml) | [`surge/paypal.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/paypal.list) |
| `crypto` | 代理 (PROXY) | [`openclash/crypto.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/crypto.yaml) | [`surge/crypto.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/crypto.list) |
| `ecommerce` | 代理 (PROXY) | [`openclash/ecommerce.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/ecommerce.yaml) | [`surge/ecommerce.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/ecommerce.list) |
| `onedrive` | 代理 (PROXY) | [`openclash/onedrive.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/onedrive.yaml) | [`surge/onedrive.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/onedrive.list) |
| `forum` | 代理 (PROXY) | [`openclash/forum.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/forum.yaml) | [`surge/forum.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/forum.list) |
| `anime` | 代理 (PROXY) | [`openclash/anime.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/anime.yaml) | [`surge/anime.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/anime.list) |
| `socialmedia` | 代理 (PROXY) | [`openclash/socialmedia.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/socialmedia.yaml) | [`surge/socialmedia.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/socialmedia.list) |
| `tiktok` | 代理 (PROXY) | [`openclash/tiktok.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/tiktok.yaml) | [`surge/tiktok.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/tiktok.list) |
| `apns` | 代理 (PROXY) | [`openclash/apns.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/apns.yaml) | [`surge/apns.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/apns.list) |
| `talkatone` | 代理 (PROXY) | [`openclash/talkatone.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/talkatone.yaml) | [`surge/talkatone.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/talkatone.list) |
| `vowifi` | 代理 (PROXY) | [`openclash/vowifi.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/vowifi.yaml) | [`surge/vowifi.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/vowifi.list) |
| `tld_proxy` | 代理 (PROXY) | [`openclash/tld_proxy.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/tld_proxy.yaml) | [`surge/tld_proxy.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/tld_proxy.list) |
| `gfw` | 代理 (PROXY) | [`openclash/gfw.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/gfw.yaml) | [`surge/gfw.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/gfw.list) |
| `global` | 代理 (PROXY) | [`openclash/global.yaml`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/openclash/global.yaml) | [`surge/global.list`](https://raw.githubusercontent.com/crescentln/Project_G/main/ruleset/dist/surge/global.list) |
## 两个合并规则的来源

### `reject`（REJECT）

- EasyList
- EasyPrivacy
- AdGuard DNS Filter
- Phishing Army（phishing 域名）
- 本地可控补充：`ruleset/manual/categories/reject.txt`

### 独立可选拦截集合

- `reject_extra`（REJECT）：`ruleset/manual/categories/reject_extra.txt`
- `reject_drop`（REJECT-DROP）：`ruleset/manual/categories/reject_drop.txt`
- `reject_no_drop`（REJECT-NO-DROP）：`ruleset/manual/categories/reject_no_drop.txt`

当前基线说明：

- `reject_extra`：更严格的广告/追踪域（adjust、appsflyer、doubleclick、taboola 等）
- `reject_drop`：高风险 OOB 回连域（dnslog/ceye/interact/oast 等）静默丢弃
- `reject_no_drop`：广告主域走显式拒绝（adservice/googleadservices/pagead2 等）

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

- 需要“单 URL”时，优先用：`openclash/<cat>.yaml`、`surge/<cat>.list`
- `non_ip`：仅域名规则
- `ip`：仅 CIDR/IP 规则
- `domainset`：纯域名集合

## 自动更新

工作流：`.github/workflows/ruleset-update.yml`

- 每周自动运行：`cron: 17 3 * * 1`（UTC）
- 先执行冲突/质量闸门（冲突、抓取回退、规则数量突变、关键分类最小条目阈值）
- 有变化时自动写入 `ruleset/dist/CHANGELOG.md` 并提交
- 同时打回滚标签：`ruleset-YYYYMMDDTHHMMSSZ`
- 有变化时自动创建 GitHub Release（tag 与快照标签一致）
- Release 说明由脚本自动生成（基于 `CHANGELOG` + 冲突/抓取统计）
- 工作流增加稳定性保护：并发互斥、构建重试（最多 3 次）和 Job 超时限制
- 使用 Actions 缓存保留 `ruleset/.cache`，提升上游源短时波动时的成功率
- 质量门允许少量抓取回退（fallback <= 30），若超阈值仍会失败并触发告警
- 失败时自动上传诊断产物（conflicts/fetch_report/policy/changelog）

### 失败邮件告警配置

当 `build-and-publish` 失败时，会触发 `notify-failure-email` job。
需要在仓库 `Settings -> Secrets and variables -> Actions` 中设置以下 Secrets：

- `SMTP_SERVER`：SMTP 服务器地址（例如 `smtp.gmail.com`）
- `SMTP_PORT`：SMTP 端口（常见 `465` 或 `587`）
- `SMTP_USERNAME`：SMTP 用户名
- `SMTP_PASSWORD`：SMTP 密码或应用专用密码
- `ALERT_EMAIL_FROM`：发件人地址（例如 `Project_G Bot <bot@example.com>`）
- `ALERT_EMAIL_TO`：收件人地址（可以是多个，用逗号分隔）

如果上述 Secrets 缺失，工作流会跳过发信并在日志中提示缺失项。

## 误杀处理流程

- 使用 GitHub Issue 模板 `Ruleset false positive` 提交误杀证据。
- 在 `ruleset/manual/allow/reject*.txt` 添加放行规则。
- CI 会自动校验放行规则是否已从对应 `reject*` 输出移除。

## 其他文档

- 全量分类与动作: `ruleset/dist/rule_catalog.md`
- 策略映射: `ruleset/dist/policy_reference.md`
- 构建与配置说明: `ruleset/README.md`
- 旧名称迁移: `ruleset/MAPPING.md`
