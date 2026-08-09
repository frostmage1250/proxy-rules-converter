# Generated rule report

This report is deterministic; no build timestamp is embedded.

## China IP (Mihomo only)

- IPv4 output entries: 3908
- IPv6 output entries: 1234
- Both providers are compiled with Mihomo behavior `ipcidr`.
- No Shadowrocket IP provider is generated.

## Domestic

- Output entries: 864
- Nonessential classical wildcard rules dropped: 1
- Exact duplicates removed: 0
- Semantically redundant entries removed: 0

## Apple direct

- Apple CDN domain entries: 158
- Apple Services domain entries: 16
- Ignored process rules: 8
- Ignored IP rules: 1
- Final combined output entries: 65
- MetaCubeX Apple and Apple@CN are intentionally not used.
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

- Generated domain sets: 13
- Static hand-maintained domain sets: 2
- APNS and Shadowrocket IP rule sets are intentionally not generated.
