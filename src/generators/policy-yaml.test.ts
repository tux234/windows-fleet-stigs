import { describe, test, expect } from "bun:test";
import { generatePolicyYaml, mergePolicyYaml } from "./policy-yaml.ts";
import type { CspReferenceDb } from "../ddf/types.ts";
import type { ExtractedSetting } from "../intune/types.ts";

function makeDb(
  nodes: Record<string, { format: string; isAdmxBacked?: boolean; description?: string }>
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
      description: config.description ?? "",
      accessType: { get: true, replace: true, add: false, delete: false, exec: false },
      isAdmxBacked: config.isAdmxBacked ?? false,
    };

    const normalized = uri
      .replace(/^\.\/(Device|User)\//, "")
      .replace(/\//g, "_")
      .toLowerCase();
    db.definitionIdIndex[normalized] = uri;
  }

  db.metadata.nodeCount = Object.keys(db.nodes).length;
  return db;
}

describe("generatePolicyYaml", () => {
  test("generates Fleet policy YAML with mdm_bridge query", () => {
    const db = makeDb({
      "./Device/Vendor/MSFT/DeviceLock/DevicePasswordEnabled": {
        format: "int",
        description: "Specifies whether device password is enabled.",
      },
    });

    const settings: ExtractedSetting[] = [
      {
        definitionId: "vendor_msft_devicelock_devicepasswordenabled_0",
        baseDefinitionId: "vendor_msft_devicelock_devicepasswordenabled",
        suffix: "_0",
        value: 0,
        formatHint: "int",
        valueType: "choice",
      },
    ];

    const summary = generatePolicyYaml(settings, db, "win11-stig");
    expect(summary.generated).toBe(1);

    const yaml = summary.results[0].yaml;
    expect(yaml).toContain("apiVersion: v1");
    expect(yaml).toContain("kind: policy");
    expect(yaml).toContain("platform: windows");
    expect(yaml).toContain("STIG -");
    expect(yaml).toContain("mdm_bridge");
    expect(yaml).toContain("SyncBody");
    expect(yaml).toContain("LocURI");
    expect(yaml).toContain("./Device/Vendor/MSFT/DeviceLock/DevicePasswordEnabled");
    expect(yaml).toContain("= '0'");
    expect(yaml).toContain("framework:DISA-STIG");
    expect(yaml).toContain("benchmark:win11-stig");
    expect(yaml).toContain("purpose: Informational");
    // Query must be inline (not >- folded scalar) per Fleet convention
    expect(yaml).toContain("query: SELECT");
    expect(yaml).not.toContain("query: >-");
  });

  test("generates ADMX LIKE query for enabled settings", () => {
    const db = makeDb({
      "./Device/Vendor/MSFT/Policy/Config/AboveLock/AllowCortanaAboveLock": {
        format: "chr",
        isAdmxBacked: true,
        description: "Allow Cortana above lock screen.",
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

    const summary = generatePolicyYaml(settings, db);
    expect(summary.generated).toBe(1);

    const yaml = summary.results[0].yaml;
    expect(yaml).toContain("LIKE '%<Disabled/>%'");
    // Compliance queries use Policy/Result/ not Policy/Config/
    expect(yaml).toContain("Policy/Result/");
    expect(yaml).not.toContain("Policy/Config/");
  });

  test("generates ADMX LIKE query for disabled settings", () => {
    const db = makeDb({
      "./Device/Vendor/MSFT/Policy/Config/Test/Setting": {
        format: "chr",
        isAdmxBacked: true,
      },
    });

    const settings: ExtractedSetting[] = [
      {
        definitionId: "vendor_msft_policy_config_test_setting_true",
        baseDefinitionId: "vendor_msft_policy_config_test_setting",
        suffix: "_true",
        value: true,
        formatHint: "bool",
        valueType: "choice",
      },
    ];

    const summary = generatePolicyYaml(settings, db);
    const yaml = summary.results[0].yaml;
    expect(yaml).toContain("LIKE '%<Enabled/>%'");
  });

  test("reports unmapped settings", () => {
    const db = makeDb({});

    const settings: ExtractedSetting[] = [
      {
        definitionId: "vendor_msft_nonexistent_true",
        baseDefinitionId: "vendor_msft_nonexistent",
        suffix: "_true",
        value: true,
        formatHint: "bool",
        valueType: "choice",
      },
    ];

    const summary = generatePolicyYaml(settings, db);
    expect(summary.unmapped).toBe(1);
  });
});

describe("mergePolicyYaml", () => {
  test("joins YAML blocks with document separators", () => {
    const blocks = [
      "apiVersion: v1\nkind: policy\nspec:\n  name: test1",
      "apiVersion: v1\nkind: policy\nspec:\n  name: test2",
    ];

    const merged = mergePolicyYaml(blocks);
    expect(merged).toContain("---");
    expect(merged.split("---").length).toBe(2);
  });
});
