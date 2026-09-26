undefined
## Egern-native rule sets

The same workflow extracts the rule-provider model from the pinned Mihomo script,
converts every referenced text provider to Egern-native YAML, and publishes
`dist/egern/*.yaml`. It also converts the pinned
`ttyyss2233/Tool/shadowrocket/rules/apns.list` to `dist/egern/apns.yaml`.
`reports/egern-source.json` records the Mihomo, Bett, and APNs commits, exact
source URLs and hashes, preserved entry counts, and hashes of published YAML.
Generated geolocation-cn and Claude sources are read from this workflow's own
Mihomo outputs after they are validated; MRS binaries are never decoded for Egern.
The Egern profile repository consumes this report and only publishes its profile.
Published `dist/egern` paths remain stable for previously imported profiles.
