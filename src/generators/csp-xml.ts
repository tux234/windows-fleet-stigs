import type { CspReferenceDb, DdfNode } from "../ddf/types.ts";
import { lookupOmaUri, normalizeOmaUriToDefinitionId } from "../ddf/parser.ts";
import type { ExtractedSetting } from "../intune/types.ts";

/** CSP paths that Fleet blocks in custom profiles */
const BLOCKED_CSP_PREFIXES = [
  "./Device/Vendor/MSFT/BitLocker",
  "./Vendor/MSFT/BitLocker",
  "./Device/Vendor/MSFT/Policy/Config/Update",
  "./Vendor/MSFT/Policy/Config/Update",
];

export interface CspXmlResult {
  /** The OMA-URI this setting targets */
  omaUri: string;
  /** Generated XML content */
  xml: string;
  /** Status of the generation */
  status: "generated" | "blocked" | "unmapped" | "skipped";
  /** Reason for non-generated status */
  reason?: string;
}

export interface GenerationSummary {
  total: number;
  generated: number;
  blocked: number;
  unmapped: number;
  skipped: number;
  results: CspXmlResult[];
}

/**
 * Generate Fleet-compatible SyncML XML for a list of extracted Intune settings.
 */
export function generateCspXml(
  settings: ExtractedSetting[],
  db: CspReferenceDb
): GenerationSummary {
  const results: CspXmlResult[] = [];

  for (const setting of settings) {
    const result = generateSingleCsp(setting, db);
    results.push(result);
  }

  return {
    total: results.length,
    generated: results.filter((r) => r.status === "generated").length,
    blocked: results.filter((r) => r.status === "blocked").length,
    unmapped: results.filter((r) => r.status === "unmapped").length,
    skipped: results.filter((r) => r.status === "skipped").length,
    results,
  };
}

/**
 * Generate SyncML XML for a single setting.
 */
function generateSingleCsp(
  setting: ExtractedSetting,
  db: CspReferenceDb
): CspXmlResult {
  // Look up the OMA-URI from the reference database
  const node = lookupOmaUri(db, setting.baseDefinitionId);

  if (!node) {
    return {
      omaUri: setting.baseDefinitionId,
      xml: "",
      status: "unmapped",
      reason: `No DDF match for definition ID: ${setting.baseDefinitionId}`,
    };
  }

  // Check if this CSP path is blocked by Fleet
  if (isBlockedCsp(node.omaUri)) {
    return {
      omaUri: node.omaUri,
      xml: "",
      status: "blocked",
      reason: `Fleet blocks this CSP path. ${node.omaUri.includes("BitLocker") ? "Use mdm.disk_encryption endpoint instead." : "Enable EnableCustomOSUpdates to allow."}`,
    };
  }

  // Determine format and data value
  const { format, dataValue } = resolveFormatAndValue(setting, node);

  if (dataValue === null || dataValue === undefined) {
    return {
      omaUri: node.omaUri,
      xml: "",
      status: "skipped",
      reason: "Could not determine data value",
    };
  }

  const xml = buildSyncMlReplace(node.omaUri, format, dataValue);

  return {
    omaUri: node.omaUri,
    xml,
    status: "generated",
  };
}

/**
 * Resolve the SyncML format type and data value for a setting.
 */
function resolveFormatAndValue(
  setting: ExtractedSetting,
  node: DdfNode
): { format: string; dataValue: string | null } {
  // For ADMX-backed policies, always use chr format with CDATA
  if (node.isAdmxBacked || node.allowedValues?.type === "admx") {
    return resolveAdmxValue(setting, node);
  }

  // Use the DDF's format as the authoritative source
  const format = node.format;

  switch (format) {
    case "bool": {
      const boolVal = toBooleanValue(setting.value);
      return { format: "bool", dataValue: boolVal };
    }
    case "int": {
      const intVal = toIntegerValue(setting.value);
      return { format: "int", dataValue: intVal !== null ? String(intVal) : null };
    }
    case "chr": {
      const strVal = String(setting.value);
      return { format: "chr", dataValue: `<![CDATA[${strVal}]]>` };
    }
    default:
      // Fallback: use the format hint from the Intune JSON
      return resolveFromHint(setting);
  }
}

/**
 * Resolve value for ADMX-backed policies.
 * ADMX policies use chr format with XML content wrapped in CDATA.
 */
function resolveAdmxValue(
  setting: ExtractedSetting,
  _node: DdfNode
): { format: string; dataValue: string } {
  const val = setting.value;

  // Boolean true/enabled → <enabled/>
  if (val === true || val === "true" || val === 1 || val === "1") {
    return { format: "chr", dataValue: "<![CDATA[<enabled/>]]>" };
  }

  // Boolean false/disabled → <disabled/>
  if (val === false || val === "false" || val === 0 || val === "0") {
    return { format: "chr", dataValue: "<![CDATA[<disabled/>]]>" };
  }

  // String value — wrap in CDATA as-is
  return { format: "chr", dataValue: `<![CDATA[${String(val)}]]>` };
}

function resolveFromHint(setting: ExtractedSetting): {
  format: string;
  dataValue: string | null;
} {
  switch (setting.formatHint) {
    case "bool":
      return { format: "bool", dataValue: toBooleanValue(setting.value) };
    case "int":
      return {
        format: "int",
        dataValue: toIntegerValue(setting.value)?.toString() ?? null,
      };
    case "chr":
      return { format: "chr", dataValue: `<![CDATA[${String(setting.value)}]]>` };
    default:
      // Last resort: treat as int
      return {
        format: "int",
        dataValue: toIntegerValue(setting.value)?.toString() ?? null,
      };
  }
}

function toBooleanValue(val: string | number | boolean): string {
  if (val === true || val === "true" || val === 1 || val === "1") return "true";
  return "false";
}

function toIntegerValue(val: string | number | boolean): number | null {
  if (typeof val === "number") return val;
  if (typeof val === "boolean") return val ? 1 : 0;
  const parsed = parseInt(val, 10);
  return isNaN(parsed) ? null : parsed;
}

function isBlockedCsp(omaUri: string): boolean {
  const normalized = omaUri.toLowerCase();
  return BLOCKED_CSP_PREFIXES.some((prefix) =>
    normalized.startsWith(prefix.toLowerCase())
  );
}

/**
 * Build a SyncML <Replace> XML block.
 */
export function buildSyncMlReplace(
  omaUri: string,
  format: string,
  dataValue: string
): string {
  return `<Replace>
    <Item>
        <Meta>
            <Format xmlns="syncml:metinf">${format}</Format>
        </Meta>
        <Target>
            <LocURI>${omaUri}</LocURI>
        </Target>
        <Data>${dataValue}</Data>
    </Item>
</Replace>`;
}

/**
 * Merge multiple CSP XML blocks into a single file.
 */
export function mergeCspXml(xmlBlocks: string[]): string {
  return xmlBlocks.join("\n");
}

/**
 * Write a CSP XML string to a file without UTF-8 BOM (Fleet requirement).
 */
export async function writeCspXmlFile(
  content: string,
  filePath: string
): Promise<void> {
  // Bun.write uses UTF-8 without BOM by default
  await Bun.write(filePath, content);
}
