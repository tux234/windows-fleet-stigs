/** A single CSP node extracted from a DDF v2 XML file */
export interface DdfNode {
  /** Full OMA-URI path, e.g. "./Device/Vendor/MSFT/Policy/Config/AboveLock/AllowCortanaAboveLock" */
  omaUri: string;
  /** SyncML format type */
  format: "bool" | "chr" | "int" | "node" | "xml" | "b64" | "bin" | "null" | "date" | "time" | "float";
  /** Human-readable description */
  description: string;
  /** Supported access operations */
  accessType: AccessType;
  /** Default value if specified */
  defaultValue?: string;
  /** Allowed values specification */
  allowedValues?: AllowedValues;
  /** Whether this is an ADMX-backed policy */
  isAdmxBacked: boolean;
  /** ADMX details if applicable */
  admxInfo?: AdmxInfo;
}

export interface AccessType {
  get: boolean;
  replace: boolean;
  add: boolean;
  delete: boolean;
  exec: boolean;
}

export type AllowedValues =
  | { type: "enum"; values: EnumValue[] }
  | { type: "range"; min: string; max: string }
  | { type: "admx"; area: string; name: string; file: string }
  | { type: "regex"; pattern: string }
  | { type: "none" };

export interface EnumValue {
  value: string;
  description?: string;
}

export interface AdmxInfo {
  area: string;
  name: string;
  file: string;
}

/** The complete CSP reference database */
export interface CspReferenceDb {
  /** Map from OMA-URI to node details */
  nodes: Record<string, DdfNode>;
  /** Reverse index: normalized settingDefinitionId → OMA-URI */
  definitionIdIndex: Record<string, string>;
  /** Metadata about the database */
  metadata: {
    ddfVersion: string;
    generatedAt: string;
    nodeCount: number;
  };
}
