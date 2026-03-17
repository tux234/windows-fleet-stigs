import { describe, test, expect } from "bun:test";
import { generateCspXml, buildSyncMlReplace } from "./csp-xml.ts";
import type { CspReferenceDb } from "../ddf/types.ts";
import type { ExtractedSetting } from "../intune/types.ts";

function makeDb(
  nodes: Record<string, { format: string; isAdmxBacked?: boolean }>
): CspReferenceDb {
  const db: CspReferenceDb = {
    nodes: {},
    definitionIdIndex: {},
    metadata: { ddfVersion: "v2", generatedAt: "", nodeCount: 0 },
  };

  for (const [uri, config] of Object.entries(nodes)) {
    db.nodes[uri] = {
      omaUri: uri,
      format: config.format as any,
      description: "",
      accessType: { get: true, replace: true, add: false, delete: false, exec: false },
      isAdmxBacked: config.isAdmxBacked ?? false,
    };

    // Build reverse index
    const normalized = uri
      .replace(/^\.\/(Device|User)\//, "")
      .replace(/\//g, "_")
      .toLowerCase();
    db.definitionIdIndex[normalized] = uri;
  }

  db.metadata.nodeCount = Object.keys(db.nodes).length;
  return db;
}

describe("buildSyncMlReplace", () => {
  test("generates valid XML with int format", () => {
    const xml = buildSyncMlReplace(
      "./Device/Vendor/MSFT/DeviceLock/DevicePasswordEnabled",
      "int",
      "0"
    );
    expect(xml).toContain("<Format xmlns=\"syncml:metinf\">int</Format>");
    expect(xml).toContain("<LocURI>./Device/Vendor/MSFT/DeviceLock/DevicePasswordEnabled</LocURI>");
    expect(xml).toContain("<Data>0</Data>");
    expect(xml).toContain("<Replace>");
    expect(xml).toContain("</Replace>");
  });

  test("generates valid XML with bool format", () => {
    const xml = buildSyncMlReplace(
      "./Device/Vendor/MSFT/Firewall/EnableFirewall",
      "bool",
      "true"
    );
    expect(xml).toContain("<Format xmlns=\"syncml:metinf\">bool</Format>");
    expect(xml).toContain("<Data>true</Data>");
  });

  test("generates valid XML with chr format and CDATA", () => {
    const xml = buildSyncMlReplace(
      "./Device/Vendor/MSFT/Policy/Config/Test/Setting",
      "chr",
      "<![CDATA[<enabled/>]]>"
    );
    expect(xml).toContain("<Format xmlns=\"syncml:metinf\">chr</Format>");
    expect(xml).toContain("<Data><![CDATA[<enabled/>]]></Data>");
  });
});

describe("generateCspXml", () => {
  test("generates XML for known settings using DB format", () => {
    const db = makeDb({
      "./Device/Vendor/MSFT/Firewall/EnableFirewall": { format: "bool" },
    });

    const settings: ExtractedSetting[] = [
      {
        definitionId: "vendor_msft_firewall_enablefirewall_true",
        baseDefinitionId: "vendor_msft_firewall_enablefirewall",
        suffix: "_true",
        value: true,
        formatHint: "bool",
        valueType: "choice",
      },
    ];

    const summary = generateCspXml(settings, db);
    expect(summary.generated).toBe(1);
    expect(summary.results[0].status).toBe("generated");
    expect(summary.results[0].xml).toContain("<Format xmlns=\"syncml:metinf\">bool</Format>");
    expect(summary.results[0].xml).toContain("<Data>true</Data>");
  });

  test("blocks BitLocker CSP paths", () => {
    const db = makeDb({
      "./Device/Vendor/MSFT/BitLocker/RequireDeviceEncryption": { format: "int" },
    });

    const settings: ExtractedSetting[] = [
      {
        definitionId: "vendor_msft_bitlocker_requiredeviceencryption_1",
        baseDefinitionId: "vendor_msft_bitlocker_requiredeviceencryption",
        suffix: "_1",
        value: 1,
        formatHint: "int",
        valueType: "choice",
      },
    ];

    const summary = generateCspXml(settings, db);
    expect(summary.blocked).toBe(1);
    expect(summary.results[0].status).toBe("blocked");
    expect(summary.results[0].reason).toContain("disk_encryption");
  });

  test("blocks Windows Update CSP paths", () => {
    const db = makeDb({
      "./Device/Vendor/MSFT/Policy/Config/Update/AllowAutoUpdate": { format: "int" },
    });

    const settings: ExtractedSetting[] = [
      {
        definitionId: "vendor_msft_policy_config_update_allowautoupdate_1",
        baseDefinitionId: "vendor_msft_policy_config_update_allowautoupdate",
        suffix: "_1",
        value: 1,
        formatHint: "int",
        valueType: "choice",
      },
    ];

    const summary = generateCspXml(settings, db);
    expect(summary.blocked).toBe(1);
  });

  test("reports unmapped settings", () => {
    const db = makeDb({});

    const settings: ExtractedSetting[] = [
      {
        definitionId: "vendor_msft_nonexistent_setting_true",
        baseDefinitionId: "vendor_msft_nonexistent_setting",
        suffix: "_true",
        value: true,
        formatHint: "bool",
        valueType: "choice",
      },
    ];

    const summary = generateCspXml(settings, db);
    expect(summary.unmapped).toBe(1);
    expect(summary.results[0].status).toBe("unmapped");
  });

  test("handles ADMX-backed policies with chr format", () => {
    const db = makeDb({
      "./Device/Vendor/MSFT/Policy/Config/AboveLock/AllowCortanaAboveLock": {
        format: "chr",
        isAdmxBacked: true,
      },
    });

    const settings: ExtractedSetting[] = [
      {
        definitionId: "vendor_msft_policy_config_abovelock_allowcortanaabovelock_0",
        baseDefinitionId: "vendor_msft_policy_config_abovelock_allowcortanaabovelock",
        suffix: "_0",
        value: 0,
        formatHint: "int",
        valueType: "choice",
      },
    ];

    const summary = generateCspXml(settings, db);
    expect(summary.generated).toBe(1);
    expect(summary.results[0].xml).toContain("chr");
    expect(summary.results[0].xml).toContain("<![CDATA[<disabled/>]]>");
  });

  test("handles simple string settings", () => {
    const db = makeDb({
      "./Device/Vendor/MSFT/Policy/Config/Some/StringSetting": { format: "chr" },
    });

    const settings: ExtractedSetting[] = [
      {
        definitionId: "vendor_msft_policy_config_some_stringsetting",
        baseDefinitionId: "vendor_msft_policy_config_some_stringsetting",
        value: "test-value",
        formatHint: "chr",
        valueType: "string",
      },
    ];

    const summary = generateCspXml(settings, db);
    expect(summary.generated).toBe(1);
    expect(summary.results[0].xml).toContain("<![CDATA[test-value]]>");
  });
});
