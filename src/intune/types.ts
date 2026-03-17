/** A single setting extracted from an Intune JSON export */
export interface ExtractedSetting {
  /** Original Intune settingDefinitionId */
  definitionId: string;
  /** The base definition ID without value suffix */
  baseDefinitionId: string;
  /** Value suffix if present (e.g., "_true", "_1") */
  suffix?: string;
  /** Resolved value to set */
  value: string | number | boolean;
  /** SyncML format type hint from the JSON */
  formatHint?: "chr" | "int" | "bool";
  /** Simple setting value type from Intune */
  valueType?: "string" | "integer" | "choice";
  /** STIG control ID if available */
  stigControlId?: string;
}

/** Intune JSON export top-level structure */
export interface IntuneJsonExport {
  name?: string;
  description?: string;
  settings: IntuneSettingGroup[];
  /** Additional metadata */
  [key: string]: unknown;
}

export interface IntuneSettingGroup {
  settingInstance?: IntuneSettingInstance;
  [key: string]: unknown;
}

export interface IntuneSettingInstance {
  settingDefinitionId?: string;
  choiceSettingValue?: {
    value?: string;
    children?: IntuneSettingChild[];
  };
  simpleSettingValue?: {
    "@odata.type": string;
    value: string | number;
  };
  [key: string]: unknown;
}

export interface IntuneSettingChild {
  settingInstance?: IntuneSettingInstance;
  settingDefinitionId?: string;
  choiceSettingValue?: {
    value?: string;
    children?: IntuneSettingChild[];
  };
  simpleSettingValue?: {
    "@odata.type": string;
    value: string | number;
  };
}
