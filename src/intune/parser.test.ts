import { describe, test, expect } from "bun:test";
import { parseIntuneJsonString } from "./parser.ts";

describe("parseIntuneJsonString", () => {
  test("extracts choice settings with boolean suffixes", () => {
    const json = JSON.stringify({
      settings: [
        {
          settingInstance: {
            settingDefinitionId: "vendor_msft_firewall_enablefirewall",
            choiceSettingValue: {
              value: "vendor_msft_firewall_enablefirewall_true",
            },
          },
        },
      ],
    });

    const settings = parseIntuneJsonString(json);
    expect(settings.length).toBe(1);
    expect(settings[0].baseDefinitionId).toBe("vendor_msft_firewall_enablefirewall");
    expect(settings[0].suffix).toBe("_true");
    expect(settings[0].value).toBe(true);
    expect(settings[0].formatHint).toBe("bool");
  });

  test("extracts choice settings with numeric suffixes", () => {
    const json = JSON.stringify({
      settings: [
        {
          settingInstance: {
            settingDefinitionId: "vendor_msft_policy_config_system_allowtelemetry",
            choiceSettingValue: {
              value: "vendor_msft_policy_config_system_allowtelemetry_1",
            },
          },
        },
      ],
    });

    const settings = parseIntuneJsonString(json);
    expect(settings.length).toBe(1);
    expect(settings[0].suffix).toBe("_1");
    expect(settings[0].value).toBe(1);
    expect(settings[0].formatHint).toBe("int");
  });

  test("extracts simple string settings", () => {
    const json = JSON.stringify({
      settings: [
        {
          settingInstance: {
            settingDefinitionId: "vendor_msft_policy_config_some_string_setting",
            simpleSettingValue: {
              "@odata.type":
                "#microsoft.graph.deviceManagementConfigurationStringSettingValue",
              value: "hello world",
            },
          },
        },
      ],
    });

    const settings = parseIntuneJsonString(json);
    expect(settings.length).toBe(1);
    expect(settings[0].value).toBe("hello world");
    expect(settings[0].formatHint).toBe("chr");
    expect(settings[0].valueType).toBe("string");
  });

  test("extracts simple integer settings", () => {
    const json = JSON.stringify({
      settings: [
        {
          settingInstance: {
            settingDefinitionId: "vendor_msft_devicelock_mindevicepasswordlength",
            simpleSettingValue: {
              "@odata.type":
                "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
              value: 8,
            },
          },
        },
      ],
    });

    const settings = parseIntuneJsonString(json);
    expect(settings.length).toBe(1);
    expect(settings[0].value).toBe(8);
    expect(settings[0].formatHint).toBe("int");
    expect(settings[0].valueType).toBe("integer");
  });

  test("extracts child settings recursively", () => {
    const json = JSON.stringify({
      settings: [
        {
          settingInstance: {
            settingDefinitionId: "vendor_msft_firewall_parent",
            choiceSettingValue: {
              value: "vendor_msft_firewall_parent_true",
              children: [
                {
                  settingInstance: {
                    settingDefinitionId: "vendor_msft_firewall_child1",
                    choiceSettingValue: {
                      value: "vendor_msft_firewall_child1_enabled",
                    },
                  },
                },
                {
                  settingDefinitionId: "vendor_msft_firewall_child2",
                  simpleSettingValue: {
                    "@odata.type":
                      "#microsoft.graph.deviceManagementConfigurationIntegerSettingValue",
                    value: 42,
                  },
                },
              ],
            },
          },
        },
      ],
    });

    const settings = parseIntuneJsonString(json);
    expect(settings.length).toBe(3); // parent + 2 children

    // Parent
    expect(settings[0].baseDefinitionId).toBe("vendor_msft_firewall_parent");
    expect(settings[0].value).toBe(true);

    // Child 1 (choice)
    expect(settings[1].baseDefinitionId).toBe("vendor_msft_firewall_child1");
    expect(settings[1].suffix).toBe("_enabled");

    // Child 2 (simple integer)
    expect(settings[2].value).toBe(42);
  });

  test("handles _disabled and _block suffixes", () => {
    const json = JSON.stringify({
      settings: [
        {
          settingInstance: {
            settingDefinitionId: "vendor_msft_policy_config_test_disabled",
            choiceSettingValue: {
              value: "vendor_msft_policy_config_test_disabled",
            },
          },
        },
        {
          settingInstance: {
            settingDefinitionId: "vendor_msft_policy_config_test_block",
            choiceSettingValue: {
              value: "vendor_msft_policy_config_test_block",
            },
          },
        },
      ],
    });

    const settings = parseIntuneJsonString(json);
    expect(settings.length).toBe(2);
    expect(settings[0].value).toBe(false);
    expect(settings[0].suffix).toBe("_disabled");
    expect(settings[1].value).toBe(false);
    expect(settings[1].suffix).toBe("_block");
  });

  test("throws on invalid JSON structure", () => {
    expect(() => parseIntuneJsonString("{}")).toThrow("Invalid Intune JSON");
    expect(() => parseIntuneJsonString('{"settings": "not array"}')).toThrow(
      "Invalid Intune JSON"
    );
  });

  test("handles empty settings array", () => {
    const settings = parseIntuneJsonString('{"settings": []}');
    expect(settings.length).toBe(0);
  });

  test("extracts STIG control ID from profile name", () => {
    const json = JSON.stringify({
      name: "DoD Windows 11 STIG v2r4 Settings Catalog",
      settings: [
        {
          settingInstance: {
            settingDefinitionId: "device_vendor_msft_policy_config_devicelock_preventenablinglockscreencamera",
            choiceSettingValue: {
              value: "device_vendor_msft_policy_config_devicelock_preventenablinglockscreencamera_1",
            },
          },
        },
      ],
    });

    const settings = parseIntuneJsonString(json);
    expect(settings.length).toBe(1);
    expect(settings[0].stigControlId).toBeDefined();
    expect(settings[0].stigControlId).toContain("win11-stig-v2r4");
  });

  test("handles device_ prefix in DISA settingDefinitionIds", () => {
    const json = JSON.stringify({
      name: "DoD Windows 10 STIG v3r4 Settings Catalog",
      settings: [
        {
          settingInstance: {
            settingDefinitionId: "device_vendor_msft_policy_config_camera_allowcamera",
            choiceSettingValue: {
              value: "device_vendor_msft_policy_config_camera_allowcamera_0",
            },
          },
        },
      ],
    });

    const settings = parseIntuneJsonString(json);
    expect(settings.length).toBe(1);
    expect(settings[0].stigControlId).toContain("win10-stig-v3r4");
  });

  test("sets stigControlId to setting name when no STIG profile name", () => {
    const json = JSON.stringify({
      settings: [
        {
          settingInstance: {
            settingDefinitionId: "vendor_msft_firewall_enablefirewall",
            choiceSettingValue: {
              value: "vendor_msft_firewall_enablefirewall_true",
            },
          },
        },
      ],
    });

    const settings = parseIntuneJsonString(json);
    expect(settings[0].stigControlId).toBeDefined();
    expect(settings[0].stigControlId).not.toContain("stig");
  });
});
