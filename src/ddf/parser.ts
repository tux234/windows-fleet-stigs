import { readdir } from "node:fs/promises";
import { join } from "node:path";
import type {
  AccessType,
  AdmxInfo,
  AllowedValues,
  CspReferenceDb,
  DdfNode,
  EnumValue,
} from "./types.ts";

/**
 * Parse a single DDF v2 XML file and extract all CSP nodes.
 *
 * DDF structure:
 *   <MgmtTree>
 *     <Node>
 *       <NodeName>DeviceLock</NodeName>
 *       <Path>./Vendor/MSFT/Policy/Config</Path>
 *       <DFProperties>...</DFProperties>
 *       <Node>...</Node>  (children)
 *     </Node>
 *   </MgmtTree>
 */
export async function parseDdfFile(filePath: string): Promise<DdfNode[]> {
  const content = await Bun.file(filePath).text();
  const nodes: DdfNode[] = [];

  // Use regex-based extraction since Bun doesn't have a built-in XML DOM parser.
  // DDF v2 XML is well-structured enough for this approach.
  extractNodes(content, nodes);

  return nodes;
}

/**
 * Parse all DDF XML files in a directory and build the reference database.
 */
export async function buildReferenceDb(ddfDir: string): Promise<CspReferenceDb> {
  const xmlFiles = await findXmlFiles(ddfDir);
  console.log(`Parsing ${xmlFiles.length} DDF XML files...`);

  const allNodes: DdfNode[] = [];

  for (const file of xmlFiles) {
    const nodes = await parseDdfFile(file);
    allNodes.push(...nodes);
  }

  // Build primary index: OMA-URI → node
  const nodesMap: Record<string, DdfNode> = {};
  for (const node of allNodes) {
    // Skip "node" format entries (container nodes, not leaf settings)
    if (node.format === "node") continue;
    nodesMap[node.omaUri] = node;
  }

  // Build reverse index: normalized settingDefinitionId → OMA-URI
  const definitionIdIndex: Record<string, string> = {};
  const collisions: string[] = [];

  for (const omaUri of Object.keys(nodesMap)) {
    const normalizedId = normalizeOmaUriToDefinitionId(omaUri);
    if (definitionIdIndex[normalizedId] && definitionIdIndex[normalizedId] !== omaUri) {
      collisions.push(
        `Collision: "${normalizedId}" maps to both "${definitionIdIndex[normalizedId]}" and "${omaUri}"`
      );
    }
    definitionIdIndex[normalizedId] = omaUri;
  }

  if (collisions.length > 0) {
    console.warn(`WARNING: ${collisions.length} definition ID collisions detected:`);
    for (const c of collisions.slice(0, 10)) {
      console.warn(`  ${c}`);
    }
  }

  const db: CspReferenceDb = {
    nodes: nodesMap,
    definitionIdIndex,
    metadata: {
      ddfVersion: "v2",
      generatedAt: new Date().toISOString(),
      nodeCount: Object.keys(nodesMap).length,
    },
  };

  console.log(
    `Built reference DB: ${db.metadata.nodeCount} leaf nodes, ${Object.keys(definitionIdIndex).length} definition IDs`
  );

  return db;
}

/**
 * Normalize an OMA-URI to match Intune's settingDefinitionId format.
 *
 * ./Device/Vendor/MSFT/Policy/Config/AboveLock/AllowCortanaAboveLock
 *   → vendor_msft_policy_config_abovelock_allowcortanaabovelock
 *
 * This is the key insight from FirstPrinciples: go URI → ID (deterministic),
 * not ID → URI (ambiguous).
 */
export function normalizeOmaUriToDefinitionId(omaUri: string): string {
  return omaUri
    .replace(/^\.\/(Device\/|User\/)?/, "") // Strip ./Device/, ./User/, or just ./
    .replace(/\//g, "_")                    // Slash → underscore
    .toLowerCase();                         // Lowercase everything
}

/**
 * Look up an OMA-URI from a settingDefinitionId using the reference database.
 *
 * Handles the `device_` / `user_` prefix that DISA STIG JSON files add to
 * settingDefinitionIds (e.g., `device_vendor_msft_...` → `vendor_msft_...`).
 */
export function lookupOmaUri(
  db: CspReferenceDb,
  definitionId: string
): DdfNode | undefined {
  const normalized = definitionId.toLowerCase();

  // Direct lookup first
  let omaUri = db.definitionIdIndex[normalized];
  if (omaUri) return db.nodes[omaUri];

  // Strip device_/user_ prefix (DISA JSON format → DDF format)
  const stripped = normalized.replace(/^(device|user)_/, "");
  omaUri = db.definitionIdIndex[stripped];
  if (omaUri) return db.nodes[omaUri];

  return undefined;
}

// ─── Internal XML Parsing ────────────────────────────────────────────

async function findXmlFiles(dir: string): Promise<string[]> {
  const files: string[] = [];
  const entries = await readdir(dir, { withFileTypes: true, recursive: true });
  for (const entry of entries) {
    if (entry.isFile() && entry.name.endsWith(".xml")) {
      const fullPath = entry.parentPath
        ? join(entry.parentPath, entry.name)
        : join(dir, entry.name);
      files.push(fullPath);
    }
  }
  return files;
}

/**
 * Extract DDF Node elements from XML content.
 *
 * Strategy: Find all leaf <Node> elements (those with DFProperties containing
 * a non-"node" DFFormat) and reconstruct their full OMA-URI from NodeName + Path.
 */
function extractNodes(xml: string, results: DdfNode[]): void {
  // Match each <Node>...</Node> block (non-greedy, handling nesting via iteration)
  // We process the flat list of Node elements and use Path + NodeName to build URIs
  const nodePattern = /<Node>\s*<NodeName>(.*?)<\/NodeName>(.*?)<\/Node>/gs;
  let match: RegExpExecArray | null;

  // First pass: extract all nodes with their properties
  const rawNodes: Array<{
    nodeName: string;
    path?: string;
    properties: string;
    fullBlock: string;
  }> = [];

  // Better approach: walk the XML structure level by level
  parseNodeTree(xml, "", results);
}

/**
 * Recursively parse the DDF Node tree structure.
 */
function parseNodeTree(xml: string, parentPath: string, results: DdfNode[]): void {
  // Find top-level <Node> elements at this nesting level
  const topNodes = findTopLevelNodes(xml);

  for (const nodeXml of topNodes) {
    const nodeName = extractTag(nodeXml, "NodeName");
    if (!nodeName) continue;

    // Path can be explicitly specified or inherited
    const explicitPath = extractTag(nodeXml, "Path");
    const fullPath = explicitPath
      ? `${explicitPath}/${nodeName}`
      : parentPath
        ? `${parentPath}/${nodeName}`
        : nodeName;

    // Extract DFProperties
    const dfProps = extractBlock(nodeXml, "DFProperties");
    if (dfProps) {
      const format = extractFormat(dfProps);
      const description = extractTag(dfProps, "Description") ?? "";
      const accessType = extractAccessType(dfProps);
      const defaultValue = extractTag(dfProps, "DefaultValue");
      const allowedValues = extractAllowedValues(dfProps);
      const admxInfo = extractAdmxInfo(dfProps);

      if (format && format !== "node") {
        results.push({
          omaUri: fullPath,
          format: format as DdfNode["format"],
          description,
          accessType,
          defaultValue: defaultValue ?? undefined,
          allowedValues,
          isAdmxBacked: !!admxInfo || allowedValues?.type === "admx",
          admxInfo,
        });
      }
    }

    // Recurse into child nodes — extract inner content of this <Node>
    // Strip the outer <Node>...</Node> wrapper and DFProperties to get children only
    const innerContent = getNodeInnerContent(nodeXml);
    if (innerContent.includes("<Node>")) {
      parseNodeTree(innerContent, fullPath, results);
    }
  }
}

/**
 * Find top-level <Node> elements, handling nesting correctly.
 */
function findTopLevelNodes(xml: string): string[] {
  const nodes: string[] = [];
  let depth = 0;
  let startIdx = -1;

  // Simple state machine to find balanced <Node>...</Node> pairs
  let i = 0;
  while (i < xml.length) {
    if (xml.startsWith("<Node>", i) || xml.startsWith("<Node ", i)) {
      if (depth === 0) {
        startIdx = i;
      }
      depth++;
      i += 6;
    } else if (xml.startsWith("</Node>", i)) {
      depth--;
      if (depth === 0 && startIdx >= 0) {
        nodes.push(xml.substring(startIdx, i + 7));
        startIdx = -1;
      }
      i += 7;
    } else {
      i++;
    }
  }

  return nodes;
}

function extractTag(xml: string, tag: string): string | null {
  const match = xml.match(new RegExp(`<${tag}>([\\s\\S]*?)<\\/${tag}>`, "i"));
  return match ? match[1].trim() : null;
}

function extractBlock(xml: string, tag: string): string | null {
  const match = xml.match(new RegExp(`<${tag}>[\\s\\S]*?<\\/${tag}>`, "i"));
  return match ? match[0] : null;
}

/**
 * Get the inner content of a <Node> block, stripping the outer tags and
 * only the FIRST DFProperties (belonging to this node, not children).
 * This prevents infinite recursion when looking for child <Node> elements.
 */
function getNodeInnerContent(nodeXml: string): string {
  // Remove the outermost <Node>...</Node> wrapper
  let inner = nodeXml.replace(/^<Node[^>]*>/, "").replace(/<\/Node>\s*$/, "");
  // Remove only the first NodeName and Path (belonging to this node)
  inner = inner.replace(/<NodeName>[\s\S]*?<\/NodeName>/, "");
  inner = inner.replace(/<Path>[\s\S]*?<\/Path>/, "");
  // Remove only the FIRST DFProperties block (this node's properties, not children's)
  inner = inner.replace(/<DFProperties>[\s\S]*?<\/DFProperties>/, "");
  return inner;
}

function extractFormat(dfProps: string): string | null {
  const dfFormat = extractBlock(dfProps, "DFFormat");
  if (!dfFormat) return null;

  // Format is indicated by the presence of a specific empty element
  const formats = ["b64", "bin", "bool", "chr", "int", "node", "null", "xml", "date", "time", "float"];
  for (const f of formats) {
    if (dfFormat.includes(`<${f}`)) return f;
  }
  return null;
}

function extractAccessType(dfProps: string): AccessType {
  const block = extractBlock(dfProps, "AccessType") ?? "";
  return {
    get: block.includes("<Get"),
    replace: block.includes("<Replace"),
    add: block.includes("<Add"),
    delete: block.includes("<Delete"),
    exec: block.includes("<Exec"),
  };
}

function extractAllowedValues(dfProps: string): AllowedValues | undefined {
  // Check for MSFT:AllowedValues
  const avMatch = dfProps.match(
    /<(?:MSFT:)?AllowedValues[\s\S]*?ValueType="(\w+)"[\s\S]*?>([\s\S]*?)<\/(?:MSFT:)?AllowedValues>/i
  );
  if (!avMatch) return undefined;

  const valueType = avMatch[1];
  const content = avMatch[2];

  switch (valueType) {
    case "ENUM": {
      const values: EnumValue[] = [];
      const enumPattern = /<(?:MSFT:)?Enum>[\s\S]*?<(?:MSFT:)?Value>(.*?)<\/(?:MSFT:)?Value>(?:[\s\S]*?<(?:MSFT:)?ValueDescription>(.*?)<\/(?:MSFT:)?ValueDescription>)?[\s\S]*?<\/(?:MSFT:)?Enum>/gi;
      let enumMatch: RegExpExecArray | null;
      while ((enumMatch = enumPattern.exec(content)) !== null) {
        values.push({
          value: enumMatch[1].trim(),
          description: enumMatch[2]?.trim(),
        });
      }
      return { type: "enum", values };
    }
    case "Range": {
      const rangeValue = extractTag(content, "Value") ?? extractTag(content, "MSFT:Value");
      if (rangeValue) {
        const rangeMatch = rangeValue.match(/\[(\d+)-(\d+)\]/);
        if (rangeMatch) {
          return { type: "range", min: rangeMatch[1], max: rangeMatch[2] };
        }
      }
      return undefined;
    }
    case "ADMX": {
      const admxMatch = content.match(
        /<(?:MSFT:)?AdmxBacked\s+Area="([^"]+)"\s+Name="([^"]+)"\s+File="([^"]+)"/i
      );
      if (admxMatch) {
        return { type: "admx", area: admxMatch[1], name: admxMatch[2], file: admxMatch[3] };
      }
      return undefined;
    }
    case "RegEx": {
      const pattern = extractTag(content, "Value") ?? extractTag(content, "MSFT:Value");
      return pattern ? { type: "regex", pattern } : undefined;
    }
    default:
      return { type: "none" };
  }
}

function extractAdmxInfo(dfProps: string): AdmxInfo | undefined {
  const match = dfProps.match(
    /<(?:MSFT:)?AdmxBacked\s+Area="([^"]+)"\s+Name="([^"]+)"\s+File="([^"]+)"/i
  );
  if (!match) return undefined;
  return { area: match[1], name: match[2], file: match[3] };
}
