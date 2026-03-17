import { describe, test, expect } from "bun:test";
import { normalizeOmaUriToDefinitionId, parseDdfFile, buildReferenceDb, lookupOmaUri } from "./parser.ts";
import { join } from "node:path";
import { mkdir } from "node:fs/promises";

describe("normalizeOmaUriToDefinitionId", () => {
  test("converts simple OMA-URI to definition ID", () => {
    expect(
      normalizeOmaUriToDefinitionId("./Device/Vendor/MSFT/Policy/Config/AboveLock/AllowCortanaAboveLock")
    ).toBe("vendor_msft_policy_config_abovelock_allowcortanaabovelock");
  });

  test("strips ./Device/ prefix", () => {
    expect(
      normalizeOmaUriToDefinitionId("./Device/Vendor/MSFT/Firewall/EnableFirewall")
    ).toBe("vendor_msft_firewall_enablefirewall");
  });

  test("strips ./User/ prefix", () => {
    expect(
      normalizeOmaUriToDefinitionId("./User/Vendor/MSFT/Policy/Config/Start/HideAppList")
    ).toBe("vendor_msft_policy_config_start_hideapplist");
  });

  test("handles ADMX paths with underscores", () => {
    // ADMX_NetworkConnections has an underscore that's part of the name
    expect(
      normalizeOmaUriToDefinitionId("./Device/Vendor/MSFT/Policy/Config/ADMX_NetworkConnections/NC_ShowSharedAccessUI")
    ).toBe("vendor_msft_policy_config_admx_networkconnections_nc_showsharedaccessui");
  });

  test("lowercases everything", () => {
    expect(
      normalizeOmaUriToDefinitionId("./Device/Vendor/MSFT/DeviceLock/MaxInactivityTimeDeviceLock")
    ).toBe("vendor_msft_devicelock_maxinactivitytimedevicelock");
  });
});

describe("parseDdfFile", () => {
  test("parses a minimal DDF XML file", async () => {
    const tmpDir = join(import.meta.dir, "../../.test-tmp");
    await mkdir(tmpDir, { recursive: true });

    const testXml = `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
  <VerDTD>1.2</VerDTD>
  <MSFT:Diagnostics></MSFT:Diagnostics>
  <Node>
    <NodeName>DeviceLock</NodeName>
    <Path>./Vendor/MSFT</Path>
    <DFProperties>
      <AccessType><Get/></AccessType>
      <DFFormat><node/></DFFormat>
      <DFType><DDFName>DeviceLock</DDFName></DFType>
    </DFProperties>
    <Node>
      <NodeName>DevicePasswordEnabled</NodeName>
      <DFProperties>
        <AccessType><Get/><Replace/></AccessType>
        <DefaultValue>1</DefaultValue>
        <Description>Specifies whether device password is enabled.</Description>
        <DFFormat><int/></DFFormat>
        <DFType><MIME>text/plain</MIME></DFType>
        <MSFT:AllowedValues ValueType="ENUM">
          <MSFT:Enum>
            <MSFT:Value>0</MSFT:Value>
            <MSFT:ValueDescription>Disabled</MSFT:ValueDescription>
          </MSFT:Enum>
          <MSFT:Enum>
            <MSFT:Value>1</MSFT:Value>
            <MSFT:ValueDescription>Enabled</MSFT:ValueDescription>
          </MSFT:Enum>
        </MSFT:AllowedValues>
      </DFProperties>
    </Node>
  </Node>
</MgmtTree>`;

    const testFile = join(tmpDir, "test-ddf.xml");
    await Bun.write(testFile, testXml);

    const nodes = await parseDdfFile(testFile);

    // Should have 1 leaf node (the int one, not the container "node" type)
    const leafNodes = nodes.filter(n => n.format !== "node");
    expect(leafNodes.length).toBe(1);

    const node = leafNodes[0];
    expect(node.omaUri).toBe("./Vendor/MSFT/DeviceLock/DevicePasswordEnabled");
    expect(node.format).toBe("int");
    expect(node.description).toBe("Specifies whether device password is enabled.");
    expect(node.accessType.get).toBe(true);
    expect(node.accessType.replace).toBe(true);
    expect(node.accessType.add).toBe(false);
    expect(node.defaultValue).toBe("1");
    expect(node.isAdmxBacked).toBe(false);
  });

  test("parses ADMX-backed policy nodes", async () => {
    const tmpDir = join(import.meta.dir, "../../.test-tmp");
    await mkdir(tmpDir, { recursive: true });

    const testXml = `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
  <VerDTD>1.2</VerDTD>
  <MSFT:Diagnostics></MSFT:Diagnostics>
  <Node>
    <NodeName>AllowCortanaAboveLock</NodeName>
    <Path>./Vendor/MSFT/Policy/Config/AboveLock</Path>
    <DFProperties>
      <AccessType><Get/><Replace/></AccessType>
      <Description>Allow Cortana above lock screen.</Description>
      <DFFormat><chr/></DFFormat>
      <DFType><MIME>text/plain</MIME></DFType>
      <MSFT:AllowedValues ValueType="ADMX">
        <MSFT:AdmxBacked Area="AboveLock" Name="AllowCortanaAboveLock" File="ControlPanel.admx"/>
      </MSFT:AllowedValues>
    </DFProperties>
  </Node>
</MgmtTree>`;

    const testFile = join(tmpDir, "test-admx.xml");
    await Bun.write(testFile, testXml);

    const nodes = await parseDdfFile(testFile);
    expect(nodes.length).toBe(1);

    const node = nodes[0];
    expect(node.omaUri).toBe("./Vendor/MSFT/Policy/Config/AboveLock/AllowCortanaAboveLock");
    expect(node.format).toBe("chr");
    expect(node.isAdmxBacked).toBe(true);
    expect(node.admxInfo?.area).toBe("AboveLock");
    expect(node.admxInfo?.name).toBe("AllowCortanaAboveLock");
    expect(node.admxInfo?.file).toBe("ControlPanel.admx");
  });

  test("parses enum allowed values", async () => {
    const tmpDir = join(import.meta.dir, "../../.test-tmp");
    await mkdir(tmpDir, { recursive: true });

    const testXml = `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
  <VerDTD>1.2</VerDTD>
  <MSFT:Diagnostics></MSFT:Diagnostics>
  <Node>
    <NodeName>AllowTelemetry</NodeName>
    <Path>./Vendor/MSFT/Policy/Config/System</Path>
    <DFProperties>
      <AccessType><Get/><Replace/></AccessType>
      <Description>Allow telemetry.</Description>
      <DFFormat><int/></DFFormat>
      <DFType><MIME>text/plain</MIME></DFType>
      <MSFT:AllowedValues ValueType="ENUM">
        <MSFT:Enum>
          <MSFT:Value>0</MSFT:Value>
          <MSFT:ValueDescription>Security</MSFT:ValueDescription>
        </MSFT:Enum>
        <MSFT:Enum>
          <MSFT:Value>1</MSFT:Value>
          <MSFT:ValueDescription>Basic</MSFT:ValueDescription>
        </MSFT:Enum>
        <MSFT:Enum>
          <MSFT:Value>2</MSFT:Value>
          <MSFT:ValueDescription>Enhanced</MSFT:ValueDescription>
        </MSFT:Enum>
        <MSFT:Enum>
          <MSFT:Value>3</MSFT:Value>
          <MSFT:ValueDescription>Full</MSFT:ValueDescription>
        </MSFT:Enum>
      </MSFT:AllowedValues>
    </DFProperties>
  </Node>
</MgmtTree>`;

    const testFile = join(tmpDir, "test-enum.xml");
    await Bun.write(testFile, testXml);

    const nodes = await parseDdfFile(testFile);
    expect(nodes.length).toBe(1);

    const node = nodes[0];
    expect(node.allowedValues?.type).toBe("enum");
    if (node.allowedValues?.type === "enum") {
      expect(node.allowedValues.values.length).toBe(4);
      expect(node.allowedValues.values[0].value).toBe("0");
      expect(node.allowedValues.values[0].description).toBe("Security");
    }
  });
});

describe("buildReferenceDb", () => {
  test("builds database from directory of XML files", async () => {
    const tmpDir = join(import.meta.dir, "../../.test-tmp/db-test");
    await mkdir(tmpDir, { recursive: true });

    // Write two test DDF files
    const xml1 = `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
  <VerDTD>1.2</VerDTD>
  <MSFT:Diagnostics></MSFT:Diagnostics>
  <Node>
    <NodeName>EnableFirewall</NodeName>
    <Path>./Vendor/MSFT/Firewall</Path>
    <DFProperties>
      <AccessType><Get/><Replace/></AccessType>
      <Description>Enable the firewall.</Description>
      <DFFormat><bool/></DFFormat>
      <DFType><MIME>text/plain</MIME></DFType>
    </DFProperties>
  </Node>
</MgmtTree>`;

    const xml2 = `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
  <VerDTD>1.2</VerDTD>
  <MSFT:Diagnostics></MSFT:Diagnostics>
  <Node>
    <NodeName>AllowCortanaAboveLock</NodeName>
    <Path>./Vendor/MSFT/Policy/Config/AboveLock</Path>
    <DFProperties>
      <AccessType><Get/><Replace/></AccessType>
      <Description>Allow Cortana above lock.</Description>
      <DFFormat><int/></DFFormat>
      <DFType><MIME>text/plain</MIME></DFType>
    </DFProperties>
  </Node>
</MgmtTree>`;

    await Bun.write(join(tmpDir, "firewall.xml"), xml1);
    await Bun.write(join(tmpDir, "policy.xml"), xml2);

    const db = await buildReferenceDb(tmpDir);

    expect(db.metadata.nodeCount).toBe(2);
    expect(db.nodes["./Vendor/MSFT/Firewall/EnableFirewall"]).toBeDefined();
    expect(db.nodes["./Vendor/MSFT/Firewall/EnableFirewall"].format).toBe("bool");
    expect(db.nodes["./Vendor/MSFT/Policy/Config/AboveLock/AllowCortanaAboveLock"]).toBeDefined();

    // Test reverse index
    const node = lookupOmaUri(db, "vendor_msft_firewall_enablefirewall");
    expect(node).toBeDefined();
    expect(node!.omaUri).toBe("./Vendor/MSFT/Firewall/EnableFirewall");
    expect(node!.format).toBe("bool");
  });

  test("lookupOmaUri handles device_ prefix from DISA JSON", async () => {
    const tmpDir = join(import.meta.dir, "../../.test-tmp/db-device-prefix");
    await mkdir(tmpDir, { recursive: true });

    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<MgmtTree>
  <VerDTD>1.2</VerDTD>
  <Node>
    <NodeName>AllowCamera</NodeName>
    <Path>./Vendor/MSFT/Policy/Config/Camera</Path>
    <DFProperties>
      <AccessType><Get/><Replace/></AccessType>
      <Description>Allow camera.</Description>
      <DFFormat><int/></DFFormat>
      <DFType><MIME>text/plain</MIME></DFType>
    </DFProperties>
  </Node>
</MgmtTree>`;

    await Bun.write(join(tmpDir, "camera.xml"), xml);
    const db = await buildReferenceDb(tmpDir);

    // Lookup with device_ prefix (as DISA JSON provides)
    const node = lookupOmaUri(db, "device_vendor_msft_policy_config_camera_allowcamera");
    expect(node).toBeDefined();
    expect(node!.omaUri).toBe("./Vendor/MSFT/Policy/Config/Camera/AllowCamera");
  });
});
