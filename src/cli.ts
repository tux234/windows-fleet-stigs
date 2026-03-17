#!/usr/bin/env bun
import { parseArgs } from "node:util";
import { mkdir } from "node:fs/promises";
import { join, basename } from "node:path";
import { downloadDdf, getAvailableVersions } from "./ddf/download.ts";
import { buildReferenceDb } from "./ddf/parser.ts";
import { parseIntuneJson } from "./intune/parser.ts";
import { generateCspXml, mergeCspXml, writeCspXmlFile } from "./generators/csp-xml.ts";
import { generatePolicyYaml, mergePolicyYaml } from "./generators/policy-yaml.ts";
import { downloadStigPackage, extractStigMetadata, getAvailableStigVersions } from "./stig/download.ts";
import type { CspReferenceDb } from "./ddf/types.ts";

const USAGE = `
windows-fleet-stigs — Convert DISA STIG Intune policies to Fleet CSP profiles

COMMANDS:
  build-db       Download Microsoft DDF v2 files and build CSP reference database
  download-stig  Download DISA STIG Intune Policy Package from cyber.mil
  convert        Convert Intune STIG JSON to Fleet CSP XML and/or Policy YAML

build-db OPTIONS:
  --version <ver>    DDF version to download (default: feb2026)
                     Available: ${getAvailableVersions().join(", ")}
  --output <dir>     Output directory for database (default: ./data)

download-stig OPTIONS:
  --version <ver>    STIG package version (default: july2025)
                     Available: ${getAvailableStigVersions().join(", ")}
  --output <dir>     Output directory (default: ./data/stig)

convert OPTIONS:
  --input <file>     Path to Intune STIG JSON export (required)
  --db <file>        Path to reference database JSON (default: ./data/csp-reference-db.json)
  --output <dir>     Output directory (default: ./output)
  --enforcement      Generate CSP XML enforcement profiles only
  --compliance       Generate policy YAML compliance checks only
  --stig-id <id>     STIG identifier for tagging (default: DISA-STIG)

EXAMPLES:
  bun run src/cli.ts build-db
  bun run src/cli.ts download-stig
  bun run src/cli.ts convert --input data/stig/stig-july2025/Settings\\ Catalog/DoD\\ Windows\\ 11\\ STIG\\ v2r4.json
  bun run src/cli.ts convert --input stig-export.json --enforcement
`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === "--help" || command === "-h") {
    console.log(USAGE);
    process.exit(0);
  }

  switch (command) {
    case "build-db":
      await handleBuildDb(args.slice(1));
      break;
    case "download-stig":
      await handleDownloadStig(args.slice(1));
      break;
    case "convert":
      await handleConvert(args.slice(1));
      break;
    default:
      console.error(`Unknown command: ${command}`);
      console.log(USAGE);
      process.exit(1);
  }
}

async function handleBuildDb(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      version: { type: "string", default: "feb2026" },
      output: { type: "string", default: "./data" },
    },
  });

  const outputDir = values.output!;
  const version = values.version!;

  console.log(`\n=== Building CSP Reference Database ===`);
  console.log(`DDF Version: ${version}`);
  console.log(`Output: ${outputDir}\n`);

  // Download DDF files
  const ddfDir = join(outputDir, "ddf-raw");
  const xmlFiles = await downloadDdf(ddfDir, version);
  console.log(`\nDownloaded ${xmlFiles.length} DDF XML files\n`);

  // Build reference database
  const db = await buildReferenceDb(join(ddfDir, `ddf-${version}`));

  // Save database
  const dbPath = join(outputDir, "csp-reference-db.json");
  await Bun.write(dbPath, JSON.stringify(db, null, 2));
  console.log(`\nReference database saved to ${dbPath}`);
  console.log(`  Nodes: ${db.metadata.nodeCount}`);
  console.log(`  Definition IDs: ${Object.keys(db.definitionIdIndex).length}`);
}

async function handleDownloadStig(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      version: { type: "string", default: "july2025" },
      output: { type: "string", default: "./data/stig" },
    },
  });

  const outputDir = values.output!;
  const version = values.version!;

  console.log(`\n=== Downloading DISA STIG Intune Policy Package ===`);
  console.log(`Version: ${version}`);
  console.log(`Output: ${outputDir}\n`);

  const pkg = await downloadStigPackage(outputDir, version);

  console.log(`\n=== STIG Profiles Found ===`);
  for (const profile of pkg.profiles) {
    try {
      const metadata = await extractStigMetadata(profile.filePath);
      profile.metadata = metadata;
      console.log(`  ${metadata.name}`);
      console.log(`    OS: ${metadata.osTarget} | Version: ${metadata.stigVersion} | Settings: ${metadata.settingCount}`);
    } catch {
      console.log(`  ${profile.profileName} (could not extract metadata)`);
    }
  }

  console.log(`\nSTIG package extracted to: ${pkg.extractDir}`);
  console.log(`Use 'convert --input <profile.json>' to generate Fleet profiles.`);
}

async function handleConvert(args: string[]): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      input: { type: "string" },
      db: { type: "string", default: "./data/csp-reference-db.json" },
      output: { type: "string", default: "./output" },
      enforcement: { type: "boolean", default: false },
      compliance: { type: "boolean", default: false },
      merge: { type: "boolean", default: false },
      "stig-id": { type: "string", default: "DISA-STIG" },
    },
  });

  if (!values.input) {
    console.error("Error: --input is required");
    process.exit(1);
  }

  // If neither flag set, generate both
  const genEnforcement = values.enforcement || (!values.enforcement && !values.compliance);
  const genCompliance = values.compliance || (!values.enforcement && !values.compliance);

  console.log(`\n=== Converting STIG Intune JSON to Fleet Profiles ===`);
  console.log(`Input: ${values.input}`);
  console.log(`Database: ${values.db}`);
  console.log(`Output: ${values.output}`);
  console.log(`Enforcement: ${genEnforcement}`);
  console.log(`Compliance: ${genCompliance}`);
  console.log(`Merge: ${values.merge}\n`);

  // Load reference database
  const dbFile = Bun.file(values.db!);
  if (!(await dbFile.exists())) {
    console.error(`Reference database not found at ${values.db}`);
    console.error("Run 'build-db' first to create it.");
    process.exit(1);
  }
  const db: CspReferenceDb = await dbFile.json();

  // Parse Intune JSON
  const settings = await parseIntuneJson(values.input);
  console.log(`Extracted ${settings.length} settings from Intune JSON\n`);

  await mkdir(values.output!, { recursive: true });

  // Generate enforcement CSP XML
  if (genEnforcement) {
    const xmlDir = join(values.output!, "enforcement");
    await mkdir(xmlDir, { recursive: true });

    const summary = generateCspXml(settings, db);
    console.log(`=== Enforcement CSP XML ===`);
    console.log(`  Total: ${summary.total}`);
    console.log(`  Generated: ${summary.generated}`);
    console.log(`  Blocked: ${summary.blocked}`);
    console.log(`  Unmapped: ${summary.unmapped}`);
    console.log(`  Skipped: ${summary.skipped}\n`);

    const generatedResults = summary.results.filter((r) => r.status === "generated");

    // Always write merged file
    const merged = mergeCspXml(generatedResults.map((r) => r.xml));
    const mergedPath = join(xmlDir, "merged-stig-enforcement.xml");
    await writeCspXmlFile(merged, mergedPath);
    console.log(`  Merged: ${mergedPath}`);

    // Always write individual files
    const individualDir = join(xmlDir, "individual");
    await mkdir(individualDir, { recursive: true });
    for (const result of generatedResults) {
      const safeName = omaUriToFilename(result.omaUri) + ".xml";
      await writeCspXmlFile(result.xml, join(individualDir, safeName));
    }
    console.log(`  Individual: ${generatedResults.length} files in ${individualDir}`);

    // Write summary log
    const logPath = join(values.output!, "enforcement-log.json");
    await Bun.write(logPath, JSON.stringify(summary, null, 2));
    console.log(`  Log: ${logPath}\n`);
  }

  // Generate compliance Policy YAML
  if (genCompliance) {
    const yamlDir = join(values.output!, "compliance");
    await mkdir(yamlDir, { recursive: true });

    const summary = generatePolicyYaml(settings, db, values["stig-id"]!);
    console.log(`=== Compliance Policy YAML ===`);
    console.log(`  Total: ${summary.total}`);
    console.log(`  Generated: ${summary.generated}`);
    console.log(`  Unmapped: ${summary.unmapped}`);
    console.log(`  Skipped: ${summary.skipped}\n`);

    const generatedResults = summary.results.filter((r) => r.status === "generated");

    // Always write merged file
    const mergedYaml = mergePolicyYaml(generatedResults.map((r) => r.yaml));
    const mergedYamlPath = join(yamlDir, "merged-stig-compliance.yaml");
    await Bun.write(mergedYamlPath, mergedYaml);
    console.log(`  Merged: ${mergedYamlPath}`);

    // Always write individual files
    const individualYamlDir = join(yamlDir, "individual");
    await mkdir(individualYamlDir, { recursive: true });
    for (const result of generatedResults) {
      const safeName = omaUriToFilename(result.omaUri) + ".yaml";
      await Bun.write(join(individualYamlDir, safeName), result.yaml);
    }
    console.log(`  Individual: ${generatedResults.length} files in ${individualYamlDir}`);

    // Write summary log
    const logPath = join(values.output!, "compliance-log.json");
    await Bun.write(logPath, JSON.stringify(summary, null, 2));
    console.log(`  Log: ${logPath}\n`);
  }

  console.log("Conversion complete!");
}

/**
 * Convert an OMA-URI to a clean, readable filename.
 * ./Device/Vendor/MSFT/Policy/Config/DeviceLock/AllowCamera → devicelock-allowcamera
 * ./Vendor/MSFT/Firewall/MdmStore/PrivateProfile/EnableFirewall → firewall-privateprofile-enablefirewall
 */
function omaUriToFilename(omaUri: string): string {
  // Strip common prefixes to get the meaningful part
  let path = omaUri
    .replace(/^\.\/Device\/Vendor\/MSFT\/Policy\/Config\//, "")
    .replace(/^\.\/Vendor\/MSFT\/Policy\/Config\//, "")
    .replace(/^\.\/Device\/Vendor\/MSFT\//, "")
    .replace(/^\.\/Vendor\/MSFT\//, "");

  return path
    .replace(/\//g, "-")
    .toLowerCase();
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
