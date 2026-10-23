import { generateKeyPairSync, sign, X509Certificate } from "node:crypto";
import { oid, ROOT_CERTIFICATE, tlv } from "./v1SignatureBlock.js";

/** Explicit PEM framing makes Node parse these exact DER bytes. */
export const certificatePem = (der: Uint8Array): string =>
  `-----BEGIN CERTIFICATE-----\n${Buffer.from(der).toString("base64")}\n-----END CERTIFICATE-----\n`;

/** Self-signed outer certificate carrying an unrelated PEM in an ordinary extension. */
export const embeddedPemCertificate = () => {
  const { privateKey, publicKey } = generateKeyPairSync("ec", {
    namedCurve: "prime256v1",
  });
  const name = tlv(
    0x30,
    tlv(
      0x31,
      tlv(0x30, oid("2.5.4.3"), tlv(0x0c, Buffer.from("REA Outer Metadata"))),
    ),
  );
  const algorithm = tlv(0x30, oid("1.2.840.10045.4.3.2"));
  const extension = tlv(
    0x30,
    oid("1.3.6.1.4.1.55555.1"),
    tlv(
      0x04,
      tlv(0x0c, Buffer.from(`\n${certificatePem(ROOT_CERTIFICATE)}\n`)),
    ),
  );
  const tbs = tlv(
    0x30,
    tlv(0xa0, tlv(0x02, Uint8Array.of(2))),
    tlv(0x02, Uint8Array.of(0x04, 0xd2)),
    algorithm,
    name,
    tlv(
      0x30,
      tlv(0x17, Buffer.from("260101000000Z")),
      tlv(0x17, Buffer.from("300101000000Z")),
    ),
    name,
    publicKey.export({ type: "spki", format: "der" }),
    tlv(0xa3, tlv(0x30, extension)),
  );
  const der = tlv(
    0x30,
    tbs,
    algorithm,
    tlv(0x03, Uint8Array.of(0), sign("sha256", tbs, privateKey)),
  );
  return {
    der,
    publicKey,
    reference: new X509Certificate(certificatePem(der)),
  };
};
