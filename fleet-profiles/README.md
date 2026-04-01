# Fleet STIG Profiles — Generated 2026-04-01

Auto-generated from DISA STIG Intune Policy Package (`july2025`) using DDF v2 (`feb2026`).

| Profile | Enforcement CSPs | Compliance Policies | Blocked | Unmapped |
|---------|-----------------|--------------------|---------|-----------| 
| `avd---mde-exclusion-configurations` | 2 | 2 | 0 | 0 |
| `dod-internet-explorer-11-stig-v2r6` | 119 | 119 | 0 | 87 |
| `dod-microsoft-defender-antivirus-stig-computer-v2r4` | 14 | 14 | 0 | 5 |
| `dod-windows-10-stig-v3r4` | 169 | 171 | 2 | 32 |
| `dod-windows-11-stig-v2r4` | 167 | 169 | 2 | 29 |
| `dod-windows-defender-firewall-stig-v2r2` | 11 | 11 | 0 | 0 |
| `multi-session-os-dod-windows-11-stig-v2r4-comp` | 161 | 163 | 2 | 29 |
| `multi-session-os-dod-windows-11-stig-v2r4-user` | 5 | 5 | 0 | 0 |

## Usage

**Enforcement**: Upload `enforcement/merged-stig-enforcement.xml` to Fleet via Controls > OS settings > Custom settings > Add profile

**Compliance**: Import `compliance/merged-stig-compliance.yaml` via Policies > Add policy > Import or `fleetctl apply -f`

**Blocked CSPs**: BitLocker (use Fleet's disk encryption endpoint) and Windows Update (requires `EnableCustomOSUpdates`) are excluded. See enforcement-log.json for details.
