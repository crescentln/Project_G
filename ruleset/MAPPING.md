# Mapping (Old Names -> New URLs)

Base URL:

`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist`

## 当前主策略

- 统一合并：`reject`、`direct`
- 其余分类保持颗粒度，不做统一大合并

## 合并规则（你现在固定可用）

### OpenClash

- `reject`：`.../openclash/reject.yaml`
- `direct`：`.../openclash/direct.yaml`

### Surge

- `reject`：`.../surge/reject.list`
- `direct`：`.../surge/direct.list`

## 旧规则名合并关系

以下旧集合统一并入 `reject`：

- `reject`
- `reject_extra`
- `reject_drop`
- `reject_no_drop`

以下旧直连集合统一并入 `direct`：

- `lan` `domestic` `cncidr`
- `apple_cn` `apple_cdn` `microsoft_cdn`
- `games_cn` `socialmedia_cn` `douyin`
- `cdn` `download` `dmca`

## 保持颗粒度（示例）

下面这些继续独立维护和独立引用：

- `ai` `telegram` `stream_us` `stream_jp` `stream_hk` `stream_tw`
- `google` `googlefcm` `microsoft` `gits`
- `youtube` `abema` `apple_tv` `primevideo` `spotify` `twitch`
- `paypal` `crypto` `ecommerce` `onedrive` `forum` `socialmedia` `tiktok`
- `gfw` `global` `tld_proxy`

## 高覆盖补充（可选）

- `gfw`：`.../openclash/gfw.yaml` / `.../surge/gfw.list`
- `global`：`.../openclash/global.yaml` / `.../surge/global.list`
- `tld_proxy`：`.../openclash/tld_proxy.yaml` / `.../surge/tld_proxy.list`

## 兼容旧风格路径（可选）

- Clash 兼容：`.../compat/Clash/non_ip/<category>.txt`
- Surge 兼容：`.../compat/List/non_ip/<category>.conf`

全量分类和动作请看：`ruleset/dist/rule_catalog.md`
