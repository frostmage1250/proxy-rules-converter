from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(shutil.which("node"), "Node.js is required for script model extraction")
class NativeModelExtractionTests(unittest.TestCase):
    def extract(self, home: bool) -> dict:
        definitions = r"""
const regionDefinitions = [{name:"日本",regex:/日本/i}];
const rateRegionDefinitions = [
  {name:"低倍率节点",regex:/0\.5x/i},
  {name:"高倍率节点",regex:/3x/i}
];
const ruleOptionsEnable = {屏蔽国外QUIC:true};
const excludeFilter = /官网/i;
const blockForeignQuic = [];
"""
        if home:
            definitions += r"""
const homeRegionDefinitions = [{name:"家宽节点",regex:/家宽/i}];
const allRegionDefinitions = [...regionDefinitions,...rateRegionDefinitions,...homeRegionDefinitions];
const lowRateRegionName = "低倍率节点";
const highRateRegionName = "高倍率节点";
"""
        source = definitions + r"""
function main(config) {
  if (!config.proxies.length || config.proxies.some(proxy=>proxy.server!=="192.0.2.1")) {
    throw new Error("Extractor must supply isolated placeholder nodes");
  }
  const definitions = [...regionDefinitions,...rateRegionDefinitions,
    ...(typeof homeRegionDefinitions==="undefined"?[]:homeRegionDefinitions)];
  return {
    "rule-providers": {private_ip:{type:"inline",behavior:"ipcidr",payload:["192.168.0.0/16"]}},
    rules:["RULE-SET,private_ip,Direct","MATCH,Final"],
    "proxy-groups": [
      {name:"Proxy",proxies:["订阅",...definitions.map(entry=>entry.name)]},
      {name:"订阅",proxies:config.proxies.map(proxy=>proxy.name)},
      ...definitions.map(entry=>({name:entry.name,
        proxies:config.proxies.filter(proxy=>entry.regex.test(proxy.name)).map(proxy=>proxy.name)}))
    ],
    dns:{nameserver:["https://dns.example/dns-query#Proxy"]},
    hosts:{"dns.example":["192.0.2.53"]}
  };
}
"""
        with tempfile.TemporaryDirectory() as directory:
            script = Path(directory) / "mihomoScript.js"
            script.write_text(source, encoding="utf-8")
            result = subprocess.run(
                ["node", str(ROOT / "src" / "extract_mihomo_model.js"), str(script)],
                check=True, capture_output=True, text=True, encoding="utf-8",
            )
        return json.loads(result.stdout)

    def test_extracts_public_entry_point_without_old_global_variables(self):
        model = self.extract(home=True)
        self.assertEqual(model["rules"][-2:], ["RULE-SET,private_ip,Direct", "MATCH,Final"])
        self.assertIn("private_ip", model["providers"])
        self.assertEqual([entry["name"] for entry in model["homeRegions"]], ["家宽节点"])
        self.assertEqual([entry["name"] for entry in model["rateRegions"]], ["低倍率节点", "高倍率节点"])
        for group in model["groups"][2:]:
            self.assertTrue(group["proxies"], group["name"])
            self.assertTrue(all(name.startswith("__") for name in group["proxies"]))
        self.assertEqual(model["dns"]["nameserver"], ["https://dns.example/dns-query#Proxy"])

    def test_extracts_pinned_scripts_without_home_definitions(self):
        model = self.extract(home=False)
        self.assertEqual(model["homeRegions"], [])
        self.assertEqual(model["highRateRegionName"], "高倍率节点")
        self.assertEqual(model["lowRateRegionName"], "低倍率节点")
