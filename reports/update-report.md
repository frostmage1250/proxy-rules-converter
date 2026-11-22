# Generated rule report

- Conversion policy: syntax only; source order kept; only identical rules are deduplicated.
- Unsupported syntax and required normalization fail the build.

## pron

- category-porn domain rules: 6521; regex rules excluded: 140.
- Selected websites: 26; selected domain rules: 76.
- Source scope: category-porn only; E-Hentai and ExHentai excluded.
- Output rules: 76 (dist/mihomo/porn.mrs, dist/classical/porn.list).

## MCDN block

- Local rules: 4; accepted AdGuard rules: 33.
- Identical duplicates removed: 2.
- The user-excluded *pcdn*.biliapi.net wildcard is omitted.
- Output rules: 35 (dist/mihomo/mcdn-block.mrs, dist/classical/mcdn-block.list).

## Claude

- Bett Anthropic rules: 21; supplement rules (config/claude-supplement.list): 22.
- Identical duplicates removed: 8.
- Output rules: 36, ending with PROCESS-NAME,claude.exe (dist/mihomo/claude.list).
