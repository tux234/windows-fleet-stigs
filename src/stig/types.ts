/** Metadata extracted from a DISA STIG Intune Policy Package */
export interface StigMetadata {
  /** Profile name from JSON (e.g., "DoD Windows 11 STIG v2r4 Settings Catalog") */
  name: string;
  /** Description from JSON */
  description: string;
  /** Extracted OS target (e.g., "Windows 11", "Windows 10") */
  osTarget: string;
  /** STIG version string (e.g., "v2r4") */
  stigVersion: string;
  /** Number of settings in the profile */
  settingCount: number;
  /** Platform from JSON (e.g., "windows10") */
  platform: string;
}

/** Available STIG profiles in a downloaded package */
export interface StigProfile {
  /** File path to the Settings Catalog JSON */
  filePath: string;
  /** Profile name extracted from filename */
  profileName: string;
  /** Metadata extracted from the JSON content */
  metadata?: StigMetadata;
}

/** STIG package download result */
export interface StigPackage {
  /** Directory containing extracted files */
  extractDir: string;
  /** All Settings Catalog JSON profiles found */
  profiles: StigProfile[];
  /** Package version identifier (e.g., "july2025") */
  packageVersion: string;
}
