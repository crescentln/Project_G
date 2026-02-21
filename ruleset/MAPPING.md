# Rule Name Mapping (Your Current Config -> New Outputs)

Replace `<owner>/<repo>` with your GitHub repo path.

Policy reference (recommended DIRECT/PROXY/REJECT per category):

`.../ruleset/dist/policy_reference.md`

Example base URL:

`https://raw.githubusercontent.com/<owner>/<repo>/main/ruleset/dist`

Sukka-style compatibility base URL:

`https://raw.githubusercontent.com/<owner>/<repo>/main/ruleset/dist/compat`

## OpenClash

`skk_reject_domainset` -> `.../ruleset/dist/compat/Clash/domainset/reject.txt`  
`skk_reject_non_ip` -> `.../ruleset/dist/compat/Clash/non_ip/reject.txt`  
`skk_reject_ip` -> `.../ruleset/dist/compat/Clash/ip/reject.txt`  
`skk_reject_extra_domainset` -> `.../ruleset/dist/compat/Clash/domainset/reject_extra.txt`  
`skk_reject_drop_non_ip` -> `.../ruleset/dist/compat/Clash/non_ip/reject_drop.txt`  
`skk_reject_no_drop_non_ip` -> `.../ruleset/dist/compat/Clash/non_ip/reject_no_drop.txt`  

`skk_lan_non_ip` -> `.../ruleset/dist/compat/Clash/non_ip/lan.txt`  
`skk_lan_ip` -> `.../ruleset/dist/compat/Clash/ip/lan.txt`  

`skk_cdn_domainset` -> `.../ruleset/dist/compat/Clash/domainset/cdn.txt`  
`skk_cdn_non_ip` -> `.../ruleset/dist/compat/Clash/non_ip/cdn.txt`  

`skk_download_domainset` -> `.../ruleset/dist/compat/Clash/domainset/download.txt`  
`skk_download_non_ip` -> `.../ruleset/dist/compat/Clash/non_ip/download.txt`  

`skk_stream_us_non_ip` -> `.../ruleset/dist/compat/Clash/non_ip/stream_us.txt`  
`skk_stream_us_ip` -> `.../ruleset/dist/compat/Clash/ip/stream_us.txt`  
`skk_stream_jp_non_ip` -> `.../ruleset/dist/compat/Clash/non_ip/stream_jp.txt`  
`skk_stream_jp_ip` -> `.../ruleset/dist/compat/Clash/ip/stream_jp.txt`  
`skk_stream_hk_non_ip` -> `.../ruleset/dist/compat/Clash/non_ip/stream_hk.txt`  
`skk_stream_hk_ip` -> `.../ruleset/dist/compat/Clash/ip/stream_hk.txt`  
`skk_stream_tw_non_ip` -> `.../ruleset/dist/compat/Clash/non_ip/stream_tw.txt`  
`skk_stream_tw_ip` -> `.../ruleset/dist/compat/Clash/ip/stream_tw.txt`  

`skk_telegram_non_ip` -> `.../ruleset/dist/compat/Clash/non_ip/telegram.txt`  
`skk_telegram_ip` -> `.../ruleset/dist/compat/Clash/ip/telegram.txt`  

`skk_ai_non_ip` -> `.../ruleset/dist/compat/Clash/non_ip/ai.txt`  

`qh_httpdns` -> `.../ruleset/dist/compat/Clash/domainset/httpdns.txt`  
`qh_cn_domain` -> `.../ruleset/dist/compat/Clash/domainset/domestic.txt`  
`qh_apple_cn_domain` -> `.../ruleset/dist/compat/Clash/domainset/apple_cn.txt`  
`skk_apple_cdn_domainset` -> `.../ruleset/dist/compat/Clash/domainset/apple_cdn.txt`  
`qh_microsoft_cn_domain` -> `.../ruleset/dist/compat/Clash/domainset/microsoft_cdn.txt`  
`qh_games_cn_domain` -> `.../ruleset/dist/compat/Clash/domainset/games_cn.txt`  
`qh_cncidr_ip` -> `.../ruleset/dist/compat/Clash/ip/cncidr.txt`  

`qh_games_domain` -> `.../ruleset/dist/compat/Clash/domainset/games.txt`  
`qh_youtube_domain` -> `.../ruleset/dist/compat/Clash/domainset/youtube.txt`  
`qh_abema_domain` -> `.../ruleset/dist/compat/Clash/domainset/abema.txt`  
`qh_apple_tv_domain` -> `.../ruleset/dist/compat/Clash/domainset/apple_tv.txt`  
`qh_primevideo_domain` -> `.../ruleset/dist/compat/Clash/domainset/primevideo.txt`  
`qh_spotify_domain` -> `.../ruleset/dist/compat/Clash/domainset/spotify.txt`  
`qh_twitch_domain` -> `.../ruleset/dist/compat/Clash/domainset/twitch.txt`  

`qh_google_domain` -> `.../ruleset/dist/compat/Clash/domainset/google.txt`  
`qh_googlefcm_domain` -> `.../ruleset/dist/compat/Clash/domainset/googlefcm.txt`  
`qh_paypal_domain` -> `.../ruleset/dist/compat/Clash/domainset/paypal.txt`  
`qh_crypto_domain` -> `.../ruleset/dist/compat/Clash/domainset/crypto.txt`  
`qh_ecommerce_domain` -> `.../ruleset/dist/compat/Clash/domainset/ecommerce.txt`  
`qh_onedrive_domain` -> `.../ruleset/dist/compat/Clash/domainset/onedrive.txt`  

`qh_forum_domain` -> `.../ruleset/dist/compat/Clash/domainset/forum.txt`  
`qh_socialmedia_cn_domain` -> `.../ruleset/dist/compat/Clash/domainset/socialmedia_cn.txt`  
`qh_tiktok_domain` -> `.../ruleset/dist/compat/Clash/domainset/tiktok.txt`  
`qh_douyin_domain` -> `.../ruleset/dist/compat/Clash/domainset/douyin.txt`  
`qh_apns_domain` -> `.../ruleset/dist/compat/Clash/domainset/apns.txt`  
`qh_apple_proxy_domain` -> `.../ruleset/dist/compat/Clash/domainset/apple_proxy.txt`  
`qh_dmca_domain` -> `.../ruleset/dist/compat/Clash/domainset/dmca.txt`  

## Surge

Use RULE-SET:

`.../ruleset/dist/compat/List/non_ip/<category>.conf` or `.../ruleset/dist/surge/<category>.list`

Use DOMAIN-SET:

`.../ruleset/dist/compat/List/domainset/<category>.conf` or `.../ruleset/dist/surge/domainset/<category>.conf`

Your currently used Surge categories are all present, including:

`lan, reject, apple_cn, microsoft_cdn, domestic, apple_services, microsoft, ai, apple_intelligence, telegram, stream_us, stream_jp, gits, dmca, socialmedia_cn, games_cn, douyin, tiktok, socialmedia, forum, abema, youtube, twitch, spotify, apns, ecommerce, google, googlefcm, onedrive, paypal, talkatone, tld_proxy, games, crypto, gfw, global`.

Also available for current Surge style:

`apple_cdn, reject_extra, reject_drop, reject_no_drop`.
