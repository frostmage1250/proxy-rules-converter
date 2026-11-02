# Egern native rule converter

This branch reads the latest published `frostmage1250/mihomo-script/main/mihomoScript.js` once per run. It executes the script once with reserved placeholder nodes, collects every provider referenced by routing (including nested logical conditions) and DNS, downloads each unique source once, and publishes native YAML under `rules/`.

MRS providers are decoded from their actual referenced binaries with official Mihomo. YAML and text providers are parsed according to their behavior. Matching scopes, duplicates and within-field order are retained; native YAML groups entries by rule type. Unsupported data stops publication. APNs and the reviewed Bett/Sukka Private Relay supplement are configured in `config/sources.json`.

`rules/index.json` is only a filename/source index for checking references. No shared configuration model is published. The profile generator independently reads the Mihomo script and applies its own Egern customization manifest.

The workflow runs on this branch's source changes and manual dispatch. The matching workflow on the default `main` branch schedules a checkout of `egern` every six hours. One run downloads one script, converts once, checks the generated diff and commits the rule files and index together. `main` continues publishing the custom Mihomo providers consumed by that script.
