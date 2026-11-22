# Egern 原生规则集

本分支把 classical 文本规则（`TYPE,VALUE[,no-resolve]`）转换为 Egern 原生 YAML 规则集，发布在 `rules/` 下。

设备端引用地址：

```
https://raw.githubusercontent.com/frostmage1250/proxy-rules-converter/egern/rules/<文件名>.yaml
```

## 清单 `config/rules.json`

- `sources`：来源前缀及其基础 URL 和选项。
  - `bett`：`appshubcc/bett-rules` 的 `meta/geo` 分支，`skip_types` 跳过 `DOMAIN-REGEX`、`DOMAIN-KEYWORD`（与 Mihomo 脚本使用的 domain `.mrs` 保持一致）。
  - `custom`：本仓库 `main` 分支 `dist/` 下的自定义规则，不跳过任何类型。
- `rules`：输出文件名 → 来源，按顺序构建。来源写作 `前缀:路径`（路径中的 `@`、`!` 会自动转义）或完整 `https://` URL（如 apns）；也可写成 `{"source": "...", "skip_types": [...]}` 单独覆盖选项。

增删规则集只需改清单。

## 转换规则

| classical 类型 | Egern 字段 |
|---|---|
| `DOMAIN` | `domain_set` |
| `DOMAIN-SUFFIX` | `domain_suffix_set` |
| `DOMAIN-KEYWORD` | `domain_keyword_set` |
| `DOMAIN-WILDCARD` | `domain_wildcard_set` |
| `DOMAIN-REGEX` | `domain_regex_set` |
| `IP-CIDR` | `ip_cidr_set`；值为 IPv6 时归入 `ip_cidr6_set`（bett 把 IPv6 也写成 `IP-CIDR`） |
| `IP-CIDR6` | `ip_cidr6_set` |
| `IP-ASN` | `asn_set` |

- 忽略空行和 `#`、`//`、`;` 开头的注释；`PROCESS-NAME` 跳过；其他类型或非法值直接构建失败（报出文件和行号）。
- `no-resolve`：IP 类规则全部带 → 文件级 `no_resolve: true`；全部不带 → 不写；混用 → 构建失败。
- 每个字段只去除完全相同的值，保持首次出现的顺序；结果为空则构建失败。
- 全部来源下载、转换成功后才写文件；不删除清单之外的旧 `rules/*.yaml`。

## 本地运行

```
pip install -r requirements.txt
python src/build_rules.py                  # 构建全部
python src/build_rules.py --only cn cn-ip  # 只构建部分文件
python src/build_rules.py --check          # 有变化则非零退出，不写文件
python -m unittest discover -s tests
```

## 自动更新

`.github/workflows/update-egern.yml` 在本分支的 `config/`、`src/`、`requirements.txt` 或工作流本身变更时运行，也可手动触发；每天的定时任务放在 `main` 分支的同名工作流中。`rules/` 有变化时才由 github-actions[bot] 提交。
