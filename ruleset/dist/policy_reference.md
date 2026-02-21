# Ruleset Policy Reference

This file defines the recommended action per category.

| Category | Action | Priority | Rules | Note |
|---|---:|---:|---:|---|
| `reject` | `REJECT` | 100 | 175184 | 广告、追踪与恶意域名拦截 |
| `reject_extra` | `REJECT` | 110 | 0 | 额外补充拦截 |
| `reject_drop` | `REJECT-DROP` | 120 | 0 | 需要静默丢弃的拦截 |
| `reject_no_drop` | `REJECT-NO-DROP` | 130 | 0 | 拒绝但不使用 drop |
| `httpdns` | `REJECT` | 150 | 2 | HTTPDNS 相关域名建议拦截 |
| `lan` | `DIRECT` | 200 | 33 | 局域网与特殊保留地址直连 |
| `domestic` | `DIRECT` | 210 | 10828 | 中国大陆业务优先直连 |
| `cncidr` | `DIRECT` | 220 | 10828 | 中国大陆 IP 段直连 |
| `apple_cn` | `DIRECT` | 230 | 285 | Apple 中国区服务直连 |
| `apple_cdn` | `DIRECT` | 231 | 0 | Apple CDN 直连 |
| `microsoft_cdn` | `DIRECT` | 232 | 3 | 微软 CDN 与更新域名直连 |
| `socialmedia_cn` | `DIRECT` | 240 | 4 | 国内社交平台直连 |
| `games_cn` | `DIRECT` | 241 | 228 | 国内游戏服务直连 |
| `douyin` | `DIRECT` | 242 | 65 | 抖音国内流量直连 |
| `dmca` | `DIRECT` | 243 | 0 | 按你当前 Surge 配置作为直连类 |
| `cdn` | `DIRECT` | 250 | 1285 | CDN 回源与就近访问优先直连 |
| `download` | `DIRECT` | 251 | 5 | 下载流量默认直连以降低代理负载 |
| `telegram` | `PROXY` | 300 | 34 | Telegram 走代理 |
| `stream_us` | `PROXY` | 310 | 238 | 北美流媒体走代理 |
| `stream_jp` | `PROXY` | 311 | 25 | 日本流媒体走代理 |
| `stream_hk` | `PROXY` | 312 | 4 | 香港流媒体走代理 |
| `stream_tw` | `PROXY` | 313 | 4 | 台湾流媒体走代理 |
| `ai` | `PROXY` | 320 | 66 | AI 服务走代理 |
| `apple_proxy` | `PROXY` | 321 | 3 | Apple 国际域名走代理 |
| `apple_services` | `PROXY` | 322 | 1522 | Apple 服务组走代理 |
| `apple_intelligence` | `PROXY` | 323 | 5 | Apple Intelligence 走代理 |
| `microsoft` | `PROXY` | 324 | 422 | 微软国际服务走代理 |
| `gits` | `PROXY` | 325 | 40 | Git 托管平台走代理 |
| `games` | `PROXY` | 326 | 788 | 国际游戏服务走代理 |
| `youtube` | `PROXY` | 327 | 176 | YouTube 走代理 |
| `abema` | `PROXY` | 328 | 21 | Abema 走代理 |
| `apple_tv` | `PROXY` | 329 | 8 | Apple TV+ 走代理 |
| `primevideo` | `PROXY` | 330 | 23 | Prime Video 走代理 |
| `spotify` | `PROXY` | 331 | 23 | Spotify 走代理 |
| `twitch` | `PROXY` | 332 | 32 | Twitch 走代理 |
| `google` | `PROXY` | 333 | 727 | Google 主服务走代理 |
| `googlefcm` | `PROXY` | 334 | 15 | Google FCM 推送走代理 |
| `paypal` | `PROXY` | 335 | 233 | PayPal 走代理 |
| `crypto` | `PROXY` | 336 | 74 | 加密交易站点走代理 |
| `ecommerce` | `PROXY` | 337 | 1093 | 跨境电商走代理 |
| `onedrive` | `PROXY` | 338 | 11 | OneDrive 走代理 |
| `forum` | `PROXY` | 339 | 97 | 国际论坛走代理 |
| `socialmedia` | `PROXY` | 340 | 536 | 国际社交网络走代理 |
| `tiktok` | `PROXY` | 341 | 35 | TikTok 国际站走代理 |
| `apns` | `PROXY` | 342 | 2 | APNS 按你当前策略走代理 |
| `talkatone` | `PROXY` | 343 | 1 | Talkatone 走代理 |
| `tld_proxy` | `PROXY` | 344 | 0 | 需要强制代理的 TLD 集 |
| `gfw` | `PROXY` | 345 | 0 | GFW 列表走代理 |
| `global` | `PROXY` | 900 | 0 | 兜底代理集合（应放在较后顺序） |

Action definitions:
- `DIRECT`: bypass proxy.
- `PROXY`: route via proxy policy group.
- `REJECT`: deny with standard reject.
- `REJECT-DROP`: silently drop packets.
- `REJECT-NO-DROP`: explicit reject without drop.
