import type { CspReferenceDb, DdfNode } from "../ddf/types.ts";
import { lookupOmaUri } from "../ddf/parser.ts";
import type { ExtractedSetting } from "../intune/types.ts";

export interface PolicyYamlResult {
  omaUri: string;
  yaml: string;
  status: "generated" | "unmapped" | "skipped";
  reason?: string;
}

export interface PolicyGenerationSummary {
  total: number;
  generated: number;
  unmapped: number;
  skipped: number;
  results: PolicyYamlResult[];
}

/**
 * Generate Fleet-compatible policy YAML for compliance verification.
 * Matches the format used in fleet/ee/cis/win-11-intune/.
 */
export function generatePolicyYaml(
  settings: ExtractedSetting[],
  db: CspReferenceDb,
  stigId = "DISA-STIG"
): PolicyGenerationSummary {
  const results: PolicyYamlResult[] = [];

  for (const setting of settings) {
    const result = generateSinglePolicy(setting, db, stigId);
    results.push(result);
  }

  return {
    total: results.length,
    generated: results.filter((r) => r.status === "generated").length,
    unmapped: results.filter((r) => r.status === "unmapped").length,
    skipped: results.filter((r) => r.status === "skipped").length,
    results,
  };
}

/**
 * Generate a single Fleet policy YAML entry.
 */
function generateSinglePolicy(
  setting: ExtractedSetting,
  db: CspReferenceDb,
  stigId: string
): PolicyYamlResult {
  const node = lookupOmaUri(db, setting.baseDefinitionId);

  if (!node) {
    return {
      omaUri: setting.baseDefinitionId,
      yaml: "",
      status: "unmapped",
      reason: `No DDF match for: ${setting.baseDefinitionId}`,
    };
  }

  const query = buildVerificationQuery(setting, node);
  if (!query) {
    return {
      omaUri: node.omaUri,
      yaml: "",
      status: "skipped",
      reason: "Could not build verification query",
    };
  }

  // Build the policy name from the OMA-URI
  const policyName = buildPolicyName(node, setting);
  const description = escapeYaml(node.description || `STIG setting: ${node.omaUri}`);
  const resolution = buildResolution(node);
  const controlId = setting.stigControlId || extractControlFromId(setting.definitionId);
  const tags = buildTags(stigId, controlId);

  const yaml = `apiVersion: v1
kind: policy
spec:
  platform: windows
  name: '${escapeYaml(policyName)}'
  query: >-
    ${query}
  purpose: Informational
  tags: ${tags}
  description: '${description}'
  resolution: '${escapeYaml(resolution)}'`;

  return {
    omaUri: node.omaUri,
    yaml,
    status: "generated",
  };
}

/**
 * Build the mdm_bridge verification query matching Fleet's CIS patterns.
 */
function buildVerificationQuery(
  setting: ExtractedSetting,
  node: DdfNode
): string | null {
  const omaUri = node.omaUri;
  const syncmlGet = `<SyncBody><Get><CmdID>1</CmdID><Item><Target><LocURI>${omaUri}</LocURI></Target></Item></Get></SyncBody>`;

  // ADMX-backed policies use LIKE patterns
  if (node.isAdmxBacked || node.allowedValues?.type === "admx") {
    return buildAdmxQuery(syncmlGet, setting);
  }

  // Integer/bool values use exact match
  const expectedValue = resolveExpectedOutput(setting, node);
  if (expectedValue === null) return null;

  return `SELECT 1 FROM mdm_bridge WHERE mdm_command_input = '${syncmlGet}' AND mdm_command_output = '${expectedValue}';`;
}

/**
 * Build ADMX verification query using LIKE patterns (matching Fleet's CIS approach).
 */
function buildAdmxQuery(
  syncmlGet: string,
  setting: ExtractedSetting
): string {
  const val = setting.value;

  if (val === true || val === "true" || val === 1 || val === "1") {
    return `SELECT 1 FROM mdm_bridge WHERE mdm_command_input = '${syncmlGet}' AND mdm_command_output LIKE '%<enabled/>%';`;
  }

  if (val === false || val === "false" || val === 0 || val === "0") {
    return `SELECT 1 FROM mdm_bridge WHERE mdm_command_input = '${syncmlGet}' AND mdm_command_output LIKE '%<disabled/>%';`;
  }

  // For specific data values within ADMX, use the data id pattern
  if (typeof val === "number") {
    return `SELECT 1 FROM mdm_bridge WHERE mdm_command_input = '${syncmlGet}' AND mdm_command_output LIKE '%<enabled%' AND mdm_command_output LIKE '%value="${val}"%';`;
  }

  return `SELECT 1 FROM mdm_bridge WHERE mdm_command_input = '${syncmlGet}' AND mdm_command_output LIKE '%${String(val)}%';`;
}

/**
 * Resolve the expected mdm_command_output for non-ADMX settings.
 */
function resolveExpectedOutput(
  setting: ExtractedSetting,
  node: DdfNode
): string | null {
  const val = setting.value;

  switch (node.format) {
    case "bool":
      return val === true || val === "true" || val === 1 ? "true" : "false";
    case "int": {
      if (typeof val === "number") return String(val);
      if (typeof val === "boolean") return val ? "1" : "0";
      const parsed = parseInt(String(val), 10);
      return isNaN(parsed) ? null : String(parsed);
    }
    case "chr":
      return String(val);
    default:
      return String(val);
  }
}

function buildPolicyName(node: DdfNode, setting: ExtractedSetting): string {
  // Extract the last path segment as the setting name
  const segments = node.omaUri.split("/");
  const settingName = segments[segments.length - 1];

  // Convert camelCase/PascalCase to readable form
  const readable = settingName
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/_/g, " ");

  const valueStr =
    setting.value === true || setting.value === 1
      ? "Enabled"
      : setting.value === false || setting.value === 0
        ? "Disabled"
        : String(setting.value);

  return `STIG - Ensure '${readable}' is set to '${valueStr}'`;
}

function buildResolution(node: DdfNode): string {
  const segments = node.omaUri.split("/");
  // Build a Settings Catalog-style path
  const catalogPath = segments.slice(4).join("\\"); // Skip ./Device/Vendor/MSFT/
  return `To establish the recommended configuration via configuration profiles, set the following Settings Catalog path. ${catalogPath}`;
}

function buildTags(stigId: string, controlId: string): string {
  return `framework:DISA-STIG, benchmark:${stigId}, platform:windows, control:${controlId}`;
}

function extractControlFromId(definitionId: string): string {
  // Try to extract a meaningful control name from the definition ID
  const parts = definitionId.split("_");
  return parts.slice(-2).join("-");
}

function escapeYaml(str: string): string {
  return str
    .replace(/'/g, "''") // Escape single quotes for YAML
    .replace(/\n/g, " ") // Collapse newlines
    .replace(/\s+/g, " ") // Collapse whitespace
    .trim();
}

/**
 * Combine multiple policy YAML entries into a single file
 * using YAML document separators (---).
 */
export function mergePolicyYaml(yamlBlocks: string[]): string {
  return yamlBlocks.join("\n---\n");
}
