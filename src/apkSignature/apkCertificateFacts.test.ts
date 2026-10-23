import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { certificatePem } from "../../tests/fixtures/apkSignature/embeddedPemCertificate.js";
import { ROOT_CERTIFICATE } from "../../tests/fixtures/apkSignature/v1SignatureBlock.js";
import { certificateFacts } from "./apkCertificateFacts.js";

it("keeps malformed DER metadata unknown instead of reading embedded PEM", () => {
  const der = Buffer.concat([
    Buffer.from([0x30, 0x00, 0x0a]),
    Buffer.from(certificatePem(ROOT_CERTIFICATE)),
  ]);
  expect(certificateFacts(der)).toEqual({
    sha256_fingerprint: createHash("sha256").update(der).digest("hex"),
    subject: null,
    issuer: null,
    serial_number: null,
    not_before: null,
    not_after: null,
    public_key_algorithm: null,
  });
});
