# Mapping (Old Names -> New URLs)

Base URL:

`https://raw.githubusercontent.com/crescentln/new-project/main/ruleset/dist`

## 推荐：从多分类迁移到 3 分类

### OpenClash

- `reject`：`.../openclash/reject.yaml`
- `direct`：`.../openclash/direct.yaml`
- `proxy`：`.../openclash/proxy.yaml`

### Surge

- `reject`：`.../surge/reject.list`
- `direct`：`.../surge/direct.list`
- `proxy`：`.../surge/proxy.list`

## 旧规则名合并关系

以下旧集合可以统一并入 `reject`：

- `reject`
- `reject_extra`
- `reject_drop`
- `reject_no_drop`

以下旧直连集合可以统一并入 `direct`：

- `lan` `domestic` `cncidr`
- `apple_cn` `apple_cdn` `microsoft_cdn`
- `games_cn` `socialmedia_cn` `douyin`
- `cdn` `download` `dmca`

以下旧代理集合可以统一并入 `proxy`：

- `ai` `telegram` `stream_*`
- `google` `googlefcm` `microsoft` `gits`
- `youtube` `abema` `apple_tv` `primevideo`
- `spotify` `twitch` `paypal` `crypto`
- `ecommerce` `onedrive` `forum` `socialmedia`
- `tiktok` `apns` `talkatone`

## 高覆盖补充（可选）

- `gfw`：`.../openclash/gfw.yaml` / `.../surge/gfw.list`
- `global`：`.../openclash/global.yaml` / `.../surge/global.list`
- `tld_proxy`：`.../openclash/tld_proxy.yaml` / `.../surge/tld_proxy.list`

## 如果你仍要细粒度旧风格路径

兼容路径仍保留：

- Clash 兼容：`.../compat/Clash/non_ip/<category>.txt`
- Surge 兼容：`.../compat/List/non_ip/<category>.conf`

全量分类和动作请看：`ruleset/dist/rule_catalog.md`
