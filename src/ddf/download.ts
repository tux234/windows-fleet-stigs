import { mkdir } from "node:fs/promises";
import { join } from "node:path";

const DDF_URLS: Record<string, string> = {
  "feb2026": "https://download.microsoft.com/download/015bd9f5-9cca-4821-8a85-a4c5f9a5d0f2/DDFv2Feb2026.zip",
  "sept2025": "https://download.microsoft.com/download/2ff2c8b9-2e3f-47af-89e6-11c19b7f0c2a/DDFv2Sept25.zip",
  "july2025": "https://download.microsoft.com/download/c85563f6-a4ed-4f3a-9a7b-e82dde2c0f4a/DDFv2July25.zip",
};

const DEFAULT_VERSION = "feb2026";

export async function downloadDdf(
  outputDir: string,
  version: string = DEFAULT_VERSION
): Promise<string[]> {
  const url = DDF_URLS[version];
  if (!url) {
    throw new Error(
      `Unknown DDF version: ${version}. Available: ${Object.keys(DDF_URLS).join(", ")}`
    );
  }

  await mkdir(outputDir, { recursive: true });
  const zipPath = join(outputDir, `ddf-${version}.zip`);

  console.log(`Downloading DDF v2 (${version}) from Microsoft...`);
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Failed to download DDF: ${response.status} ${response.statusText}`);
  }

  const buffer = await response.arrayBuffer();
  await Bun.write(zipPath, buffer);
  console.log(`Downloaded ${(buffer.byteLength / 1024 / 1024).toFixed(1)} MB to ${zipPath}`);

  // Extract ZIP using unzip command (available on macOS/Linux)
  const extractDir = join(outputDir, `ddf-${version}`);
  await mkdir(extractDir, { recursive: true });

  const proc = Bun.spawn(["unzip", "-o", zipPath, "-d", extractDir], {
    stdout: "pipe",
    stderr: "pipe",
  });
  await proc.exited;

  if (proc.exitCode !== 0) {
    const stderr = await new Response(proc.stderr).text();
    throw new Error(`Failed to extract ZIP: ${stderr}`);
  }

  // Find all XML files in extracted directory
  const glob = new Bun.Glob("**/*.xml");
  const xmlFiles: string[] = [];
  for await (const path of glob.scan({ cwd: extractDir, absolute: true })) {
    xmlFiles.push(path);
  }

  console.log(`Extracted ${xmlFiles.length} XML files to ${extractDir}`);
  return xmlFiles;
}

export function getAvailableVersions(): string[] {
  return Object.keys(DDF_URLS);
}
