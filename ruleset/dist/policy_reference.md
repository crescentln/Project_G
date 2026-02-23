# Ruleset Policy Reference

This file defines the recommended action per category.

| Category | Action | Priority | Rules | Note |
|---|---:|---:|---:|---|
| `reject` | `REJECT` | 100 | 331659 | 广告、追踪、恶意基础拦截规则 |
| `reject_extra` | `REJECT` | 110 | 10 | 额外补充拦截规则（标准拒绝） |
| `reject_drop` | `REJECT-DROP` | 120 | 5 | 静默丢弃拦截规则 |
| `reject_no_drop` | `REJECT-NO-DROP` | 130 | 6 | 显式拒绝规则（不静默丢弃） |
| `httpdns` | `REJECT` | 150 | 49 | HTTPDNS 常用于绕过本地 DNS 分流，默认建议拦截 |
| `lan` | `DIRECT` | 200 | 33 | 局域网与特殊保留地址直连 |
| `direct` | `DIRECT` | 205 | 18890 | 合并直连集合（含国内域名 + CN CIDR，简化部署） |
| `domestic` | `DIRECT` | 210 | 6727 | 中国大陆域名集合直连（domain-focused） |
| `cncidr` | `DIRECT` | 220 | 10828 | 中国大陆 IP 段直连（IP-focused） |
| `apple_cn` | `DIRECT` | 230 | 285 | Apple 中国区服务直连 |
| `apple_cdn` | `DIRECT` | 231 | 31 | Apple 更新与 CDN 域名直连 |
| `microsoft_cdn` | `DIRECT` | 232 | 171 | 微软中国区与更新/CDN 域名直连 |
| `socialmedia_cn` | `DIRECT` | 240 | 124 | 国内社交平台直连 |
| `games_cn` | `DIRECT` | 241 | 228 | 国内游戏服务直连 |
| `douyin` | `DIRECT` | 242 | 65 | 抖音国内流量直连 |
| `dmca` | `DIRECT` | 243 | 5 | 按你当前 Surge 配置作为直连类 |
| `cdn` | `DIRECT` | 250 | 1285 | CDN 回源与就近访问优先直连 |
| `download` | `DIRECT` | 251 | 12 | 安卓应用下载集合默认直连（游戏平台流量归 games） |
| `telegram` | `PROXY` | 300 | 34 | Telegram 官方 CIDR + 域名集合走代理 |
| `stream` | `PROXY` | 309 | 434 | 整合流媒体集合（含 Netflix），跨地区统一 |
| `stream_us` | `PROXY` | 310 | 340 | 北美流媒体走代理（可选细分） |
| `stream_jp` | `PROXY` | 311 | 25 | 日本流媒体走代理（可选细分） |
| `stream_hk` | `PROXY` | 312 | 15 | 香港流媒体走代理（可选细分） |
| `stream_tw` | `PROXY` | 313 | 28 | 台湾流媒体走代理（可选细分） |
| `stream_global` | `PROXY` | 314 | 288 | 国外流媒体高覆盖集合走代理（可选细分） |
| `ai` | `PROXY` | 320 | 120 | AI 服务走代理 |
| `apple_proxy` | `PROXY` | 321 | 50 | Apple 国际域名走代理（中国区见 apple_cn/apple_cdn 直连） |
| `icloud_private_relay` | `PROXY` | 321 | 13363 | iCloud Private Relay 推荐走代理（PROXY） |
| `apple_services` | `PROXY` | 322 | 1501 | Apple 国际服务走代理（中国区与更新流量优先直连） |
| `apple_intelligence` | `PROXY` | 323 | 5 | Apple Intelligence 走代理 |
| `microsoft` | `PROXY` | 324 | 422 | 微软国际服务走代理（中国区与更新/CDN 见 microsoft_cdn 直连） |
| `github` | `PROXY` | 325 | 47 | GitHub/GitLab/Gitee/Codeberg/SourceHut 等代码托管平台走代理 |
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
| `ecommerce` | `PROXY` | 337 | 1094 | 跨境电商走代理 |
| `onedrive` | `PROXY` | 338 | 11 | OneDrive 走代理 |
| `forum` | `PROXY` | 339 | 97 | 国际论坛走代理 |
| `anime` | `PROXY` | 340 | 52 | 海外动漫、漫画与成人站点走代理 |
| `socialmedia` | `PROXY` | 340 | 631 | 国际社交网络走代理 |
| `tiktok` | `PROXY` | 341 | 35 | TikTok 国际站走代理 |
| `apns` | `PROXY` | 342 | 7 | APNS 连接域名（关键端点集合，按你当前策略走代理） |
| `talkatone` | `PROXY` | 343 | 1 | Talkatone 专项域名（单 suffix 覆盖全部子域，集合小属正常） |
| `vowifi` | `PROXY` | 344 | 26 | VoWiFi/IMS/ePDG 相关域名走代理（3GPP 命名 + 美国运营商样例） |
| `tld_proxy` | `PROXY` | 345 | 1433 | 需要强制代理的 TLD 集 |
| `gfw` | `PROXY` | 346 | 109 | GFW 列表走代理 |
| `global` | `PROXY` | 900 | 23648 | 兜底代理集合（应放在较后顺序） |

Action definitions:
- `DIRECT`: bypass proxy.
- `PROXY`: route via proxy policy group.
- `REJECT`: deny with standard reject.
- `REJECT-DROP`: silently drop packets.
- `REJECT-NO-DROP`: explicit reject without drop.
