# Generated rule report

This report is deterministic; no build timestamp is embedded.

## China IP (Mihomo only)

- IPv4 output entries: 3905
- IPv6 output entries: 3406
- Both providers are compiled with Mihomo behavior `ipcidr`.
- No Shadowrocket IP provider is generated.

## Domestic

- Output entries: 864
- Nonessential classical wildcard rules dropped: 1
- Exact duplicates removed: 0
- Semantically redundant entries removed: 0

## Apple direct

- Apple CDN domain entries: 159
- Apple CN domain entries: 9
- Final combined output entries: 166
- Sources are Sukka Apple CDN and Apple CN; overlap is minimized internally.

## Apple Services

- Sukka directly converted domain entries: 15
- Finite MetaCubeX apple.com expansion entries including apex: 149
- Ignored process rules: 8
- Ignored IP rules: 1
- Final Apple Services output entries: 164
- Direct rules also covered by Services: 30
- Sukka +.apple.com is replaced by finite descendants from MetaCubeX Apple.
- MetaCubeX Apple@CN is intentionally not used; apps.apple.com is not added.
- Required order: apple-direct (DIRECT), then apple-services (proxy).
- The same canonical rules are rendered for Mihomo and Shadowrocket.
- The Apple 17.0.0.0/8 rule is intentionally not emitted.

## Global

- Sukka explicit domain entries: 1259
- MetaCubeX branch entries before exclusions: 1576
- Final output entries: 2252
- Exact duplicates removed: 71
- Semantically redundant entries removed: 439
- Expanded branches: discord, dropbox, facebook, google, pinterest, whatsapp.
- Dropped completely: blogspot, browserleaks, sci-hub.
- The same canonical rules are rendered as a Shadowrocket DOMAIN-SET.

## Microsoft (Mihomo only)

- CDN direct output entries: 51
- Microsoft proxy output entries: 212
- Finite MetaCubeX keyword expansion entries: 186
- CDN rules also covered by the proxy set: 51
- Required order: microsoft-cdn (DIRECT), then microsoft (proxy).
- No Microsoft rule is generated for Shadowrocket.

## Steam China download

- Reviewed candidates: 11
- Missing from MetaCubeX category-game-platforms-download@cn: 0
- Final output entries: 11
- Required order: steam-cn-download (DIRECT), then MetaCubeX steam (proxy).

Final entries:

- `alibaba.cdn.steampipe.steamcontent.com`
- `cdn-ali.content.steamchina.com`
- `cdn-qc.content.steamchina.com`
- `cdn-ws.content.steamchina.com`
- `dl.steam.clngaa.com`
- `lv.queniujq.cn`
- `st-bak.viv.wanwang.space`
- `st.dl.bscstorage.net`
- `st.dl.eccdnx.com`
- `trts.baishancdnx.cn`
- `xz.pphimalayanrt.com`

## Shadowrocket

- Generated bett-rules domain sets: 21
- Generated bett-rules IP/ASN sets: 8
- Generated Steam-China domain set: 1
- Static hand-maintained domain sets: 2
- APNS remains externally maintained and is not generated.
