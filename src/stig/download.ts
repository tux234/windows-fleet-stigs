import { mkdir } from "node:fs/promises";
import { join, basename } from "node:path";
import type { StigMetadata, StigPackage, StigProfile } from "./types.ts";

/**
 * DISA STIG Intune Policy Package download URLs.
 * Source: https://public.cyber.mil/stigs/gpo/
 */
const STIG_URLS: Record<string, string> = {
  july2025:
    "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Intune_Policy_Package_July_2025.zip",
};

const DEFAULT_VERSION = "july2025";

/**
 * Download and extract a DISA STIG Intune Policy Package.
 * Returns paths to all Settings Catalog JSON files found.
 */
export async function downloadStigPackage(
  outputDir: string,
  version: string = DEFAULT_VERSION
): Promise<StigPackage> {
  const url = STIG_URLS[version];
  if (!url) {
    throw new Error(
      `Unknown STIG package version: ${version}. Available: ${getAvailableStigVersions().join(", ")}`
    );
  }

  await mkdir(outputDir, { recursive: true });
  const zipPath = join(outputDir, `stig-intune-${version}.zip`);

  console.log(`Downloading DISA STIG Intune Policy Package (${version})...`);
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(
      `Failed to download STIG package: ${response.status} ${response.statusText}`
    );
  }

  const buffer = await response.arrayBuffer();
  await Bun.write(zipPath, buffer);
  console.log(
    `Downloaded ${(buffer.byteLength / 1024 / 1024).toFixed(1)} MB to ${zipPath}`
  );

  // Extract ZIP
  const extractDir = join(outputDir, `stig-${version}`);
  await mkdir(extractDir, { recursive: true });

  const proc = Bun.spawn(["unzip", "-o", zipPath, "-d", extractDir], {
    stdout: "pipe",
    stderr: "pipe",
  });
  await proc.exited;

  if (proc.exitCode !== 0) {
    const stderr = await new Response(proc.stderr).text();
    throw new Error(`Failed to extract STIG ZIP: ${stderr}`);
  }

  // Find all Settings Catalog JSON files
  const glob = new Bun.Glob("**/Settings Catalog/**/*.json");
  const profiles: StigProfile[] = [];

  for await (const path of glob.scan({ cwd: extractDir, absolute: true })) {
    profiles.push({
      filePath: path,
      profileName: basename(path, ".json"),
    });
  }

  // If no Settings Catalog subfolder, try all JSON files
  if (profiles.length === 0) {
    const fallbackGlob = new Bun.Glob("**/*.json");
    for await (const path of fallbackGlob.scan({
      cwd: extractDir,
      absolute: true,
    })) {
      profiles.push({
        filePath: path,
        profileName: basename(path, ".json"),
      });
    }
  }

  console.log(
    `Found ${profiles.length} Settings Catalog profiles in STIG package`
  );

  return { extractDir, profiles, packageVersion: version };
}

/**
 * Extract STIG metadata from a Settings Catalog JSON file.
 */
export async function extractStigMetadata(
  filePath: string
): Promise<StigMetadata> {
  const content = await Bun.file(filePath).text();
  // Strip UTF-8 BOM if present (DISA files often have BOM)
  const clean = content.charCodeAt(0) === 0xfeff ? content.slice(1) : content;
  const json = JSON.parse(clean);

  const name = json.name ?? basename(filePath, ".json");
  const description = json.description ?? "";
  const settingCount =
    json.settingCount ?? json.settings?.length ?? 0;
  const platform = json.platforms ?? "windows10";

  return {
    name,
    description,
    osTarget: extractOsTarget(name),
    stigVersion: extractStigVersion(name),
    settingCount,
    platform,
  };
}

/** Extract OS target from profile name (e.g., "Windows 11" from "DoD Windows 11 STIG v2r4") */
function extractOsTarget(name: string): string {
  const match = name.match(/Windows\s+(\d+|Server\s+\d{4})/i);
  return match ? `Windows ${match[1]}` : "Windows";
}

/** Extract STIG version from profile name (e.g., "v2r4" from "DoD Windows 11 STIG v2r4") */
function extractStigVersion(name: string): string {
  const match = name.match(/v(\d+)r(\d+)/i);
  return match ? `v${match[1]}r${match[2]}` : "unknown";
}

export function getAvailableStigVersions(): string[] {
  return Object.keys(STIG_URLS);
}
