import { describe, expect, it } from "vitest";
import type { WebNetworkCaptureRecord } from "../webNetworkCapture.js";
import { readRecordedResponseBody } from "./recordedResponseBody.js";

const recordWithContent = (
  text: unknown,
  encoding?: unknown,
  binaryField?: {
    pointer: string;
    state: "retained" | "redacted";
    content_base64: string | null;
  },
): WebNetworkCaptureRecord =>
  ({
    ordinal: 0,
    time: "2026-01-01T00:00:00Z",
    protocol: "http",
    binary_fields: binaryField ? [binaryField] : [],
    reported: {
      request: {
        method: "GET",
        url: "https://example.invalid/message",
        httpVersion: "HTTP/1.1",
        cookies: [],
        headers: [],
        queryString: [],
        headersSize: -1,
        bodySize: 0,
      },
      response: {
        status: 200,
        statusText: "OK",
        httpVersion: "HTTP/1.1",
        cookies: [],
        headers: [],
        redirectURL: "",
        headersSize: -1,
        bodySize: typeof text === "string" ? text.length : 0,
        content: {
          size: typeof text === "string" ? text.length : 0,
          mimeType: "text/plain",
          text,
          ...(encoding === undefined ? {} : { encoding }),
        },
      },
    },
  }) as unknown as WebNetworkCaptureRecord;

describe("readRecordedResponseBody", () => {
  it("returns decoded text when encoding is absent", () => {
    const record = recordWithContent("hello", undefined);
    expect(readRecordedResponseBody(record, 262144)).toEqual({
      bodyText: "hello",
    });
  });

  it("returns decoded text when encoding is null", () => {
    const record = recordWithContent("hello", null);
    expect(readRecordedResponseBody(record, 262144)).toEqual({
      bodyText: "hello",
    });
  });

  it("decodes valid UTF-8 from base64 binary fields", () => {
    const record = recordWithContent("aGVsbG8=", "base64", {
      pointer: "/response/content/text",
      state: "retained",
      content_base64: "aGVsbG8=",
    });
    expect(readRecordedResponseBody(record, 262144)).toEqual({
      bodyText: "hello",
    });
  });

  it("treats unsupported encodings as unavailable bodyText (#6889)", () => {
    for (const encoding of ["hex", "base64url", "gzip", "deflate"]) {
      const record = recordWithContent("68656c6c6f", encoding);
      expect(readRecordedResponseBody(record, 262144)).toEqual({
        bodyText: null,
      });
    }
  });
});
