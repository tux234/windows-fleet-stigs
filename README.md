# windows-fleet-stigs

Convert DISA STIG Intune policies to Fleet-compatible Windows CSP profiles and compliance policies.

## What This Does

DISA publishes [Security Technical Implementation Guides (STIGs)](https://public.cyber.mil/stigs/) for hardening Windows systems. They also publish an [Intune Policy Package](https://public.cyber.mil/stigs/gpo/) containing Settings Catalog JSON files that can be imported directly into Microsoft Intune.

[Fleet](https://fleetdm.com) enforces Windows settings via SyncML XML CSP profiles and verifies compliance via policy queries using `mdm_bridge`. This tool bridges the gap:

```
DISA STIG Intune JSON  ──►  Fleet Enforcement CSP XML  (SyncML <Replace> profiles)
                        ──►  Fleet Compliance YAML      (mdm_bridge policy queries)
```

### Key Features

- **Downloads DISA STIG packages** directly from `dl.dod.cyber.mil` (no authentication required)
- **Builds a CSP reference database** from Microsoft's DDF v2 XML files — no Windows machine or Intune enrollment needed
- **Generates enforcement profiles** as SyncML XML with correct format types (`int`, `chr`, `bool`), ADMX-backed CDATA wrapping, and Fleet-required UTF-8 without BOM
- **Generates compliance policies** as Fleet policy YAML matching the `ee/cis/` format, using `mdm_bridge` queries with SyncML Get commands
- **Automatically excludes** BitLocker CSPs (use Fleet's `mdm.disk_encryption`) and Windows Update CSPs (blocked unless `EnableCustomOSUpdates` is enabled)
- **Cross-platform** — runs on macOS, Linux, or Windows via [Bun](https://bun.sh)

## Prerequisites

- [Bun](https://bun.sh) runtime (v1.0+)
- `unzip` command (pre-installed on macOS/Linux)

```bash
# Install Bun if needed
curl -fsSL https://bun.sh/install | bash
```

## Quick Start

```bash
# Clone and install
git clone https://github.com/tux234/windows-fleet-stigs.git
cd windows-fleet-stigs
bun install

# Step 1: Build the CSP reference database (one-time, ~30s)
bun run src/cli.ts build-db

# Step 2: Download the latest DISA STIG Intune Policy Package
bun run src/cli.ts download-stig

# Step 3: Convert a STIG profile to Fleet profiles
bun run src/cli.ts convert \
  --input "data/stig/stig-july2025/Intune Policies/Settings Catalog/DoD Windows 11 STIG v2r4 Settings Catalog.json" \
  --merge
```

This produces:
- `output/enforcement/merged-stig-enforcement.xml` — SyncML XML for Fleet CSP profile upload
- `output/compliance/merged-stig-compliance.yaml` — Fleet policy YAML for compliance verification
- `output/enforcement-log.json` — detailed conversion log with per-setting status

## Commands

### `build-db` — Build CSP Reference Database

Downloads Microsoft's DDF v2 XML files and builds a queryable JSON database mapping OMA-URIs to format types, allowed values, and descriptions.

```bash
bun run src/cli.ts build-db [--version feb2026] [--output ./data]
```

Available DDF versions: `feb2026`, `sept2025`, `july2025`

### `download-stig` — Download DISA STIG Package

Downloads the DISA STIG Intune Policy Package from `dl.dod.cyber.mil` and lists all available profiles.

```bash
bun run src/cli.ts download-stig [--version july2025] [--output ./data/stig]
```

The July 2025 package includes profiles for:
| Profile | Settings |
|---------|----------|
| Windows 11 STIG v2r4 | 167 |
| Windows 10 STIG v3r4 | 172 |
| Windows Defender Firewall STIG v2r2 | 3 |
| Microsoft Defender Antivirus STIG v2r4 | 14 |
| Microsoft Edge STIG v2r3 | 57 |
| Google Chrome STIG v2r11 | 39 |
| M365 Apps STIG v3r3 | 114 |
| Internet Explorer 11 STIG v2r6 | 119 |

> **Note:** Windows Server STIGs are not available as Intune JSON — DISA only publishes those as GPO backups.

### `convert` — Convert STIG to Fleet Profiles

```bash
bun run src/cli.ts convert \
  --input <stig.json> \
  [--db ./data/csp-reference-db.json] \
  [--output ./output] \
  [--enforcement]    # CSP XML only
  [--compliance]     # Policy YAML only
  [--merge]          # Single merged file (default: individual files per setting)
  [--stig-id <id>]   # Tag identifier (default: DISA-STIG)
```

## Output Formats

### Enforcement CSP XML

Each setting becomes a SyncML `<Replace>` block:

```xml
<Replace>
    <Item>
        <Meta>
            <Format xmlns="syncml:metinf">chr</Format>
        </Meta>
        <Target>
            <LocURI>./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera</LocURI>
        </Target>
        <Data><![CDATA[<enabled/>]]></Data>
    </Item>
</Replace>
```

Upload to Fleet: **Controls > OS settings > Custom settings > Add profile**

### Compliance Policy YAML

Each setting becomes a Fleet policy with an `mdm_bridge` query:

```yaml
apiVersion: v1
kind: policy
spec:
  platform: windows
  name: 'STIG - Ensure ''Prevent Enabling Lock Screen Camera'' is set to ''Enabled'''
  query: >-
    SELECT 1 FROM mdm_bridge WHERE mdm_command_input =
    '<SyncBody><Get><CmdID>1</CmdID><Item><Target><LocURI>./Device/Vendor/MSFT/Policy/Config/DeviceLock/PreventEnablingLockScreenCamera</LocURI></Target></Item></Get></SyncBody>'
    AND mdm_command_output LIKE '%<enabled/>%';
  purpose: Informational
  tags: framework:DISA-STIG, benchmark:DISA-STIG, platform:windows, control:win11-stig-v2r4:devicelock-preventenablinglockscreencamera
  description: '...'
  resolution: '...'
```

Import to Fleet: **Policies > Add policy > Import** or via `fleetctl apply -f`

## Architecture

```
┌───────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
│  DDF v2 XML        │────►│  CSP Reference DB │────►│  Format/Type Lookup │
│  (Microsoft)       │     │  (JSON, 4200+     │     │  OMA-URI → format   │
│                    │     │   nodes)           │     │                     │
└───────────────────┘     └──────────────────┘     └─────────┬───────────┘
                                                              │
┌───────────────────┐     ┌──────────────────┐               │
│  DISA STIG Intune  │────►│  Settings         │───────────────┤
│  JSON (cyber.mil)  │     │  Extractor        │               │
└───────────────────┘     └──────────────────┘               │
                                                              ▼
                                                 ┌───────────────────────┐
                                                 │  Generator            │
                                                 ├───────────┬───────────┤
                                                 │ CSP XML    │ Policy   │
                                                 │ (enforce)  │ YAML     │
                                                 │            │ (verify) │
                                                 └───────────┴───────────┘
```

### Why DDF v2 Instead of Registry Lookups?

The original PowerShell converter (`reference/Convert-IntuneToFleetCSP.ps1`) required a Windows machine enrolled in Intune to resolve CSP paths via registry lookups at `HKLM:\SOFTWARE\Microsoft\Provisioning\NodeCache`. This tool replaces that dependency with Microsoft's published [DDF v2 XML files](https://learn.microsoft.com/en-us/windows/client-management/mdm/configuration-service-provider-ddf) — the same canonical source used to generate the Intune Settings Catalog.

The key mapping insight: Intune `settingDefinitionId` values like `device_vendor_msft_policy_config_devicelock_allowcamera` are derived from OMA-URIs by lowercasing and replacing `/` with `_`. We build this index from the DDF (deterministic direction) rather than trying to reverse it (ambiguous due to underscores in area names like `ADMX_NetworkConnections`).

## Fleet-Specific Handling

| CSP Area | Behavior | Reason |
|----------|----------|--------|
| `./Vendor/MSFT/BitLocker/*` | **Blocked** — excluded from output | Fleet requires `mdm.disk_encryption` endpoint |
| `./Vendor/MSFT/Policy/Config/Update/*` | **Blocked** — excluded from output | Fleet restricts unless `EnableCustomOSUpdates` |
| ADMX-backed policies | `chr` format with `<![CDATA[<enabled/>]]>` | ADMX policies require XML-in-CDATA wrapping |
| Compliance queries for ADMX | `LIKE '%<enabled/>%'` pattern | Matches Fleet's existing CIS benchmark format |

## Testing

```bash
bun test              # Run all 39 unit tests
bun test --watch      # Watch mode
```

Test coverage:
- DDF XML parsing (nested nodes, ADMX detection, enum values, `device_` prefix handling)
- Intune JSON extraction (choice, simple, child recursion, STIG control ID mapping)
- CSP XML generation (format types, BitLocker/Update blocking, ADMX CDATA)
- Policy YAML generation (mdm_bridge queries, ADMX LIKE patterns, merging)
- STIG metadata extraction (version parsing, UTF-8 BOM handling)

## Project Structure

```
src/
├── cli.ts                    # CLI entry point (build-db, download-stig, convert)
├── ddf/
│   ├── download.ts           # DDF v2 ZIP download and extraction
│   ├── parser.ts             # DDF XML parser and reference DB builder
│   ├── parser.test.ts        # DDF parser tests
│   └── types.ts              # DDF type definitions
├── intune/
│   ├── parser.ts             # Intune JSON settings extractor
│   ├── parser.test.ts        # Intune parser tests
│   └── types.ts              # Intune type definitions
├── generators/
│   ├── csp-xml.ts            # SyncML XML enforcement profile generator
│   ├── csp-xml.test.ts       # CSP XML tests
│   ├── policy-yaml.ts        # Fleet policy YAML compliance generator
│   └── policy-yaml.test.ts   # Policy YAML tests
└── stig/
    ├── download.ts           # DISA STIG package downloader
    ├── download.test.ts      # STIG download tests
    └── types.ts              # STIG type definitions

reference/                    # Original PowerShell converter (for reference only)
test-data/                    # Sample STIG JSON for unit tests
```

## Conversion Stats (Win11 STIG v2r4)

| Metric | Count |
|--------|-------|
| Settings extracted | 198 (167 + 31 child/nested) |
| Enforcement CSPs generated | 167 |
| Compliance policies generated | 169 |
| Blocked (BitLocker + Update) | 2 |
| Unmapped (no DDF match) | 29 |

The 29 unmapped settings (~15%) are likely newer CSP areas added after the DDF v2 February 2026 snapshot. These are logged in `enforcement-log.json` with their definition IDs for investigation.

## License

MIT
