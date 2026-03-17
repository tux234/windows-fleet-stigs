import { describe, test, expect } from "bun:test";
import { getAvailableStigVersions, extractStigMetadata } from "./download.ts";
import { join } from "node:path";

describe("getAvailableStigVersions", () => {
  test("returns at least one version", () => {
    const versions = getAvailableStigVersions();
    expect(versions.length).toBeGreaterThan(0);
    expect(versions).toContain("july2025");
  });
});

describe("extractStigMetadata", () => {
  test("extracts metadata from a Settings Catalog JSON", async () => {
    // Create a temporary test file matching DISA format
    const testData = JSON.stringify({
      name: "DoD Windows 11 STIG v2r4 Settings Catalog",
      description: "Cloned policy from DoD Windows 11 STIG v2r3",
      platforms: "windows10",
      settingCount: 167,
      settings: [],
    });

    const tmpPath = join(import.meta.dir, "../../test-data/stig-metadata-test.json");
    await Bun.write(tmpPath, testData);

    const metadata = await extractStigMetadata(tmpPath);
    expect(metadata.name).toBe("DoD Windows 11 STIG v2r4 Settings Catalog");
    expect(metadata.osTarget).toBe("Windows 11");
    expect(metadata.stigVersion).toBe("v2r4");
    expect(metadata.settingCount).toBe(167);
    expect(metadata.platform).toBe("windows10");

    // Cleanup
    await Bun.write(tmpPath, ""); // Will be cleaned up
  });

  test("extracts metadata from Windows 10 STIG name", async () => {
    const testData = JSON.stringify({
      name: "DoD Windows 10 STIG v3r4 Settings Catalog",
      settings: [{ settingInstance: {} }],
    });

    const tmpPath = join(import.meta.dir, "../../test-data/stig-metadata-test2.json");
    await Bun.write(tmpPath, testData);

    const metadata = await extractStigMetadata(tmpPath);
    expect(metadata.osTarget).toBe("Windows 10");
    expect(metadata.stigVersion).toBe("v3r4");

    await Bun.write(tmpPath, "");
  });

  test("handles UTF-8 BOM in JSON files", async () => {
    const testData = "\uFEFF" + JSON.stringify({
      name: "DoD Windows 11 STIG v2r4 Settings Catalog",
      settings: [],
    });

    const tmpPath = join(import.meta.dir, "../../test-data/stig-bom-test.json");
    await Bun.write(tmpPath, testData);

    const metadata = await extractStigMetadata(tmpPath);
    expect(metadata.name).toBe("DoD Windows 11 STIG v2r4 Settings Catalog");

    await Bun.write(tmpPath, "");
  });
});
