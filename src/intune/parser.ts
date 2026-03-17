import type {
  ExtractedSetting,
  IntuneJsonExport,
  IntuneSettingChild,
  IntuneSettingGroup,
  IntuneSettingInstance,
} from "./types.ts";

/** Known value suffixes that Intune appends to settingDefinitionIds */
const VALUE_SUFFIX_PATTERN =
  /(_true|_false|_1|_0|_enabled|_disabled|_allow|_block|_\d+)$/;

/**
 * Parse an Intune JSON export file and extract all settings.
 */
export async function parseIntuneJson(filePath: string): Promise<ExtractedSetting[]> {
  const content = await Bun.file(filePath).text();
  // Strip UTF-8 BOM if present (DISA files often have BOM)
  const clean = content.charCodeAt(0) === 0xFEFF ? content.slice(1) : content;
  const json: IntuneJsonExport = JSON.parse(clean);

  if (!json.settings || !Array.isArray(json.settings)) {
    throw new Error("Invalid Intune JSON: missing 'settings' array");
  }

  const stigId = extractStigId(json.name);
  return extractSettingsRecursive(json.settings, 0, stigId);
}

/**
 * Parse Intune JSON from a string (for testing).
 */
export function parseIntuneJsonString(content: string): ExtractedSetting[] {
  const json: IntuneJsonExport = JSON.parse(content);
  if (!json.settings || !Array.isArray(json.settings)) {
    throw new Error("Invalid Intune JSON: missing 'settings' array");
  }
  const stigId = extractStigId(json.name);
  return extractSettingsRecursive(json.settings, 0, stigId);
}

/**
 * Extract a STIG identifier from the profile name.
 * E.g., "DoD Windows 11 STIG v2r4 Settings Catalog" → "win11-stig-v2r4"
 */
function extractStigId(name?: string): string | undefined {
  if (!name) return undefined;
  const match = name.match(/Windows\s+(\d+|Server\s+\d{4})\s+STIG\s+(v\d+r\d+)/i);
  if (!match) return undefined;
  const os = match[1].toLowerCase().replace(/\s+/g, "");
  return `win${os}-stig-${match[2].toLowerCase()}`;
}

/**
 * Recursively extract settings from the nested Intune JSON structure.
 *
 * Ported from Convert-IntuneToFleetCSP.ps1 Get-IntuneSettingsRecursive (lines 367-442).
 */
function extractSettingsRecursive(
  settings: IntuneSettingGroup[],
  depth = 0,
  stigId?: string
): ExtractedSetting[] {
  const results: ExtractedSetting[] = [];

  for (const setting of settings) {
    const instance = setting.settingInstance;
    if (!instance?.settingDefinitionId) continue;

    // Build a control ID from the parent settingDefinitionId
    const controlId = buildControlId(instance.settingDefinitionId, stigId);

    // Handle choice settings — the chosen value becomes the definitionId
    if (instance.choiceSettingValue?.value) {
      const choiceId = instance.choiceSettingValue.value;
      const extracted = parseDefinitionId(choiceId, "choice");
      extracted.stigControlId = controlId;
      results.push(extracted);

      // Process children of the choice
      if (instance.choiceSettingValue.children) {
        const childSettings = flattenChildren(instance.choiceSettingValue.children, stigId);
        results.push(...childSettings);
      }
    }
    // Handle simple setting values (string, integer)
    else if (instance.simpleSettingValue) {
      const extracted = parseSimpleSetting(instance.settingDefinitionId, instance.simpleSettingValue);
      extracted.stigControlId = controlId;
      results.push(extracted);
    }
    // Bare definition ID (no value info — still extract it)
    else {
      const extracted = parseDefinitionId(instance.settingDefinitionId, "choice");
      extracted.stigControlId = controlId;
      results.push(extracted);
    }
  }

  return results;
}

/**
 * Build a control ID from the settingDefinitionId and optional STIG context.
 * Uses the last segment of the definition ID as the control name.
 */
function buildControlId(definitionId: string, stigId?: string): string {
  // Extract the meaningful part: last 1-2 segments of the definition ID
  const parts = definitionId.split("_");
  const settingName = parts.slice(-1)[0] ?? definitionId;
  const area = parts.length >= 2 ? parts[parts.length - 2] : undefined;
  const controlName = area ? `${area}-${settingName}` : settingName;
  return stigId ? `${stigId}:${controlName}` : controlName;
}

/**
 * Flatten child settings from a choiceSettingValue's children array.
 */
function flattenChildren(children: IntuneSettingChild[], stigId?: string): ExtractedSetting[] {
  const results: ExtractedSetting[] = [];

  for (const child of children) {
    if (child.settingInstance) {
      // Recurse as a setting group
      results.push(
        ...extractSettingsRecursive([{ settingInstance: child.settingInstance }], 0, stigId)
      );
    } else if (child.choiceSettingValue?.value) {
      const extracted = parseDefinitionId(child.choiceSettingValue.value, "choice");
      extracted.stigControlId = buildControlId(child.choiceSettingValue.value, stigId);
      results.push(extracted);

      if (child.choiceSettingValue.children) {
        results.push(...flattenChildren(child.choiceSettingValue.children, stigId));
      }
    } else if (child.simpleSettingValue && child.settingDefinitionId) {
      const extracted = parseSimpleSetting(child.settingDefinitionId, child.simpleSettingValue);
      extracted.stigControlId = buildControlId(child.settingDefinitionId, stigId);
      results.push(extracted);
    }
  }

  return results;
}

/**
 * Parse a definition ID, stripping the value suffix and determining the value.
 */
function parseDefinitionId(
  definitionId: string,
  valueType: "choice"
): ExtractedSetting {
  const suffixMatch = definitionId.match(VALUE_SUFFIX_PATTERN);
  const suffix = suffixMatch ? suffixMatch[1] : undefined;
  const baseId = suffix ? definitionId.replace(VALUE_SUFFIX_PATTERN, "") : definitionId;

  let value: string | number | boolean = 1;
  let formatHint: ExtractedSetting["formatHint"];

  if (suffix) {
    switch (suffix) {
      case "_true":
      case "_enabled":
      case "_allow":
        value = true;
        formatHint = "bool";
        break;
      case "_false":
      case "_disabled":
      case "_block":
        value = false;
        formatHint = "bool";
        break;
      case "_1":
        value = 1;
        formatHint = "int";
        break;
      case "_0":
        value = 0;
        formatHint = "int";
        break;
      default: {
        // Numeric suffix like _65535
        const num = parseInt(suffix.replace("_", ""), 10);
        if (!isNaN(num)) {
          value = num;
          formatHint = "int";
        }
        break;
      }
    }
  }

  return {
    definitionId,
    baseDefinitionId: baseId,
    suffix,
    value,
    formatHint,
    valueType,
  };
}

/**
 * Parse a simple setting value (string or integer).
 */
function parseSimpleSetting(
  definitionId: string,
  simpleValue: { "@odata.type": string; value: string | number }
): ExtractedSetting {
  const isString =
    simpleValue["@odata.type"] ===
    "#microsoft.graph.deviceManagementConfigurationStringSettingValue";

  return {
    definitionId,
    baseDefinitionId: definitionId,
    value: simpleValue.value,
    formatHint: isString ? "chr" : "int",
    valueType: isString ? "string" : "integer",
  };
}
