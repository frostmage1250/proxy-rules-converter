# Generated rule report

This report is deterministic; no build timestamp is embedded.

## China IP (Mihomo only)

- IPv4 output entries: 3917
- IPv6 output entries: 3429
- Both providers are compiled with Mihomo behavior `ipcidr`.
- No Shadowrocket IP provider is generated.

## Domestic

- Output entries: 864
- Nonessential classical wildcard rules dropped: 1
- Exact duplicates removed: 0
- Semantically redundant entries removed: 0

## Apple direct

- Apple CDN domain entries: 158
- Apple CN domain entries: 9
- Final combined output entries: 165
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

- CDN direct output entries: 52
- Microsoft proxy output entries: 212
- Finite MetaCubeX keyword expansion entries: 186
- CDN rules also covered by the proxy set: 51
- Required order: microsoft-cdn (DIRECT), then microsoft (proxy).
- No Microsoft rule is generated for Shadowrocket.

## Steam China download

- Reviewed candidates: 9
- Removed because domestic already covers them: 8
- Missing from both permitted game-download sources: 0
- Final output entries: 1

Final entries:

- `alibaba.cdn.steampipe.steamcontent.com`

## Shadowrocket

- Generated domain sets: 14
- Static hand-maintained domain sets: 2
- APNS and Shadowrocket IP rule sets are intentionally not generated.
