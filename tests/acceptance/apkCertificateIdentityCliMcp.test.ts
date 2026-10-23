import { createHash } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { expect } from "vitest";
import { toolContract } from "../../src/contracts/toolContracts.js";
import { apkSignatureResultSchema } from "../../src/domain/apkSignature/apkSignatureReport.js";
import { embeddedPemCertificate } from "../fixtures/apkSignature/embeddedPemCertificate.js";
import {
  APK_SIGNATURE_V2_ID,
  signedDataBlock,
  signerInfo,
  v2SchemeValue,
  withSigningBlock,
  zipWith,
} from "../fixtures/apkSignature/v1SignatureBlock.js";
import { connectLocalToolsMcp } from "../fixtures/localToolsMcp.js";
import { createTestTempDirectory } from "../fixtures/temporaryDirectory.js";
import { cliTest } from "../support/cli/cliFixture.js";

cliTest.for(["CLI", "stdio MCP"] as const)(
  "keeps APK signer facts tied to the carried DER certificate through %s",
  async (surface, { cli }) => {
    const root = await createTestTempDirectory("rea-apk-certificate-identity-");
    const { der, publicKey, reference } = embeddedPemCertificate();
    expect(reference.verify(publicKey)).toBe(true);
    expect(Buffer.from(reference.raw)).toEqual(Buffer.from(der));
    const zip = await zipWith([
      { name: "classes.dex", data: "opaque" },
      { name: "META-INF/CERT.SF", data: "Signature-Version: 1.0" },
      {
        name: "META-INF/CERT.EC",
        data: signedDataBlock({
          certificates: [der],
          signerInfos: [signerInfo({ names: der })],
        }),
      },
    ]);
    const path = join(root, "selected.apk");
    await writeFile(
      path,
      withSigningBlock(zip, [
        { id: APK_SIGNATURE_V2_ID, value: v2SchemeValue(der) },
      ]),
    );
    let document: unknown;
    if (surface === "CLI") {
      const response = await cli.run({
        arguments: [
          "inspect-apk-signature",
          path,
          "--detail",
          "complete",
          "--json",
        ],
      });
      expect(response.exitCode, response.stderr).toBe(0);
      document = response.json;
    } else {
      const mcp = await connectLocalToolsMcp();
      const response = await mcp.call("inspect_apk_signature", {
        path,
        detail: "complete",
      });
      expect(response.isError, JSON.stringify(response)).not.toBe(true);
      document = response.structuredContent;
    }
    const evidence = toolContract("inspect_apk_signature").outputSchema.parse(
      document,
    );
    const report = apkSignatureResultSchema.parse(evidence.normalized_result);
    for (const scheme of [report.schemes.v1, report.schemes.v2]) {
      expect(scheme.signers[0]?.certificate).toMatchObject({
        sha256_fingerprint: createHash("sha256").update(der).digest("hex"),
        subject: "CN=REA Outer Metadata",
        issuer: "CN=REA Outer Metadata",
        serial_number: "04D2",
        public_key_algorithm: "ec",
        not_before: "2026-01-01T00:00:00.000Z",
        not_after: "2030-01-01T00:00:00.000Z",
      });
    }
  },
);
