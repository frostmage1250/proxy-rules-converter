# Rule converter

自定义代理规则生成仓库，由 GitHub Actions 每天自动更新。

## 分支

- `main`：生成自定义规则，发布到 `dist/`。
- [`egern`](https://github.com/frostmage1250/proxy-rules-converter/tree/egern)：把 Bett（appshubcc/bett-rules）的 classical 规则和本分支 `dist/classical/`、`dist/mihomo/claude.list` 中的自定义规则转换为 Egern 原生 YAML，发布在 `rules/`。

## 产物

```text
dist/mihomo/        # 给 Mihomo 使用
  claude.list       # classical 文本（含 DOMAIN-KEYWORD / IP-ASN / PROCESS-NAME，无法编码为 .mrs）
  geolocation-cn.mrs
  mcdn-block.mrs
  porn.mrs
dist/classical/     # 给 egern 分支使用（DOMAIN-SUFFIX,x / DOMAIN,x）
  geolocation-cn.list
  mcdn-block.list
  porn.list
reports/            # summary.json、update-report.md
```

`.mrs` 由官方 Mihomo `convert-ruleset` 从 `build/`（已 gitignore）里的中间文本编译，不再发布 `+.` 格式的 `.list`。`dist/egern/*.yaml` 是旧版兼容地址，保持冻结。

## 自定义规则来源

- **claude**：Bett `geosite/anthropic` 在前，追加 `config/claude-supplement.list`（可直接编辑，只允许 DOMAIN / DOMAIN-SUFFIX / DOMAIN-KEYWORD / IP-CIDR / IP-CIDR6 / IP-ASN），完全相同的行只保留第一次出现，最后固定追加 `PROCESS-NAME,claude.exe`。
- **mcdn-block**：`config/mcdn-block.list` 的四个后缀在前，合并 AdGuard-AntiPCDN-Rules（跳过 `sources.json` 中排除的通配规则），只去除完全相同的规则。
- **porn**：按 `config/pron-sites.json` 从 Bett `category-porn` 中筛选站点域名；排除所有正则规则和 E-Hentai / ExHentai。
- **geolocation-cn**：每次拉取最新 V2Fly domain-list-community，用官方生成器展开 `geolocation-cn` 并排除 `@ads`，再由 MetaCubeX/meta-rules-converter 编译为 `.mrs`；随后用 Mihomo 解码并转换为 `dist/classical/geolocation-cn.list`。

## 工作流

- `update-rules.yml`：每天 UTC 02:23（另可手动运行，或推送 `config/`、`src/`、`tests/` 等时触发）。推送触发时先跑单元测试，然后生成全部产物，有变化才提交 `dist/` 和 `reports/`。
- `update-egern.yml`：每天 UTC 02:50。GitHub 定时任务只从默认分支触发，所以入口放在 `main`；它检出 `egern` 分支，运行该分支的 `src/build_rules.py`，有变化才提交并推送 `rules/`。

## 本地运行

```sh
python -m pip install --requirement requirements.txt
python -m unittest discover -s tests -v
python src/convert_rules.py      # 生成 claude.list、dist/classical/*、reports/ 和 build/ 中间文本
python src/convert_mrs.py        # 需要 Mihomo（--mihomo、MIHOMO_BIN 或 PATH）
```
