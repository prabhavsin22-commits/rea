import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { inspectAppleIpsInputSchema } from "../../domain/native/appleIps.js";
import {
  appleIpsBytes,
  appleIpsMetadataLine,
  appleIpsReport,
} from "../../../tests/fixtures/binaryDiagnostics/appleIps.js";
import {
  AppleIpsFormatFailure,
  AppleIpsResourceFailure,
} from "./AppleIps.errors.js";
import { parseAppleIps } from "./AppleIpsParser.js";

const input = inspectAppleIpsInputSchema.parse({
  path: "/artifacts/report.ips",
});

const artifact = (bytes: Buffer) => ({
  path: "/artifacts/report.ips",
  sha256: createHash("sha256").update(bytes).digest("hex"),
  bytes: bytes.length,
});

it("reads a 309 crash report, uppercase UUID, and lossless register", () => {
  const bytes = appleIpsBytes();
  const report = parseAppleIps(bytes, artifact(bytes), input);
  expect(report.metadata.bug_type).toBe("309");
  expect(report.exception?.type).toBe("EXC_BAD_ACCESS");
  expect(report.exception?.signal).toBe("SIGSEGV");
  expect(report.images[0]?.uuid).toBe("AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA");
  expect(report.images[0]?.source_meaning).toBe("process");
  expect(report.images[1]?.uuid_unknown).toBe(true);
  expect(report.threads[0]?.frames[0]).toMatchObject({
    role: "faulting_instruction",
    recorded_symbol: "rea_fixture_fault",
  });
  expect(report.threads[0]?.registers[0]).toMatchObject({
    name: "x0",
    value: {
      decimal: "9594637537912899908",
      hex: "0x8527000193ed4944",
    },
  });
  expect(report.classification.status).toBe("unclassified");
  expect(report.threads[0]?.frames[0]?.runtime_address?.hex).toBe(
    "0x100000338",
  );
});

it("refuses a stackshot bug_type without a crash body", () => {
  const bytes = appleIpsBytes({ bugType: "288" });
  expect(() => parseAppleIps(bytes, artifact(bytes), input)).toThrow(
    AppleIpsFormatFailure,
  );
  try {
    parseAppleIps(bytes, artifact(bytes), input);
  } catch (cause) {
    expect(cause).toMatchObject({
      kind: "unsupported",
      message: expect.stringContaining("288"),
    });
  }
});

it("fails closed on a truncated crash body", () => {
  const bytes = appleIpsBytes({ truncateBody: true });
  expect(() => parseAppleIps(bytes, artifact(bytes), input)).toThrow(
    AppleIpsFormatFailure,
  );
});

it("matches documented watchdog, guard, PAC and dyld rules", () => {
  const watchdog = parseAppleIps(
    appleIpsBytes({ terminationCode: "2343432205" }),
    artifact(appleIpsBytes({ terminationCode: "2343432205" })),
    input,
  );
  expect(watchdog.classification.matches.map((row) => row.rule)).toEqual([
    "watchdog",
  ]);
  const guard = parseAppleIps(
    appleIpsBytes({
      exceptionType: "EXC_GUARD",
      subtype: "GUARD_TYPE_FD",
    }),
    artifact(
      appleIpsBytes({ exceptionType: "EXC_GUARD", subtype: "GUARD_TYPE_FD" }),
    ),
    input,
  );
  expect(guard.classification.matches[0]?.rule).toBe("guarded_file_descriptor");
  const pac = parseAppleIps(
    appleIpsBytes({
      subtype: "KERN_INVALID_ADDRESS (possible pointer authentication failure)",
    }),
    artifact(
      appleIpsBytes({
        subtype:
          "KERN_INVALID_ADDRESS (possible pointer authentication failure)",
      }),
    ),
    input,
  );
  expect(pac.classification.matches[0]?.rule).toBe(
    "possible_pointer_authentication_failure",
  );
  const dyld = parseAppleIps(
    appleIpsBytes({
      terminationNamespace: "DYLD",
      terminationIndicator: "Library missing",
      terminationReasons: ["Library not loaded: @rpath/libreamissing.dylib"],
    }),
    artifact(
      appleIpsBytes({
        terminationNamespace: "DYLD",
        terminationIndicator: "Library missing",
        terminationReasons: ["Library not loaded: @rpath/libreamissing.dylib"],
      }),
    ),
    input,
  );
  expect(dyld.classification.matches[0]).toMatchObject({
    rule: "dyld_missing_library",
  });
});

it("treats an empty image path as omitted and accepts CRLF line endings", () => {
  const bytes = appleIpsBytes();
  const crlf = Buffer.from(appleIpsReport().replaceAll("\n", "\r\n"), "utf8");
  const report = parseAppleIps(bytes, artifact(bytes), input);
  expect(report.images[1]?.path).toBeNull();
  const crlfReport = parseAppleIps(crlf, artifact(crlf), input);
  expect(crlfReport.metadata.bug_type).toBe("309");
  expect(crlfReport.threads[0]?.frames[0]?.role).toBe("faulting_instruction");
});

it("fails closed when the image budget is exhausted", () => {
  const bytes = appleIpsBytes();
  expect(() =>
    parseAppleIps(
      bytes,
      artifact(bytes),
      inspectAppleIpsInputSchema.parse({
        path: "/artifacts/report.ips",
        max_images: 1,
      }),
    ),
  ).toThrow(AppleIpsResourceFailure);
});

const parse = (bytes: Buffer, options: Record<string, number> = {}) =>
  parseAppleIps(
    bytes,
    artifact(bytes),
    inspectAppleIpsInputSchema.parse({
      path: "/artifacts/report.ips",
      ...options,
    }),
  );

const withBody = (body: string): Buffer =>
  Buffer.from(`${appleIpsMetadataLine()}\n${body}`, "utf8");

const report = (options: Parameters<typeof appleIpsReport>[0]) =>
  parse(appleIpsBytes(options));

it("keeps ReportCrash-shaped producer facts and reports complete coverage", () => {
  const parsed = report({});
  expect(parsed.process.os_version).toEqual({
    form: "structured",
    train: "macOS 15.0",
    build: "24A335",
    release_type: "User",
    is_embedded: null,
    unlisted_keys: [],
  });
  expect(
    report({ osVersionText: "Version 15.0 (Build 24A335)" }).process.os_version,
  ).toEqual({
    form: "text",
    text: "Version 15.0 (Build 24A335)",
  });
  expect(parsed.threads[0]?.state_flavor).toBe("ARM_THREAD_STATE64");
  expect(parsed.threads[0]?.registers.map((row) => row.name)).toEqual([
    "x0",
    "x1",
    "lr",
    "esr",
    "pc",
    "far",
  ]);
  expect(parsed.threads[0]?.registers[3]).toEqual({
    name: "esr",
    value: { decimal: "2449473606", hex: "0x92000046" },
    description: "(Data Abort) byte read Translation fault",
  });
  expect(parsed.exception?.unlisted_keys).toEqual(["rawCodes"]);
  expect(parsed.termination?.unlisted_keys).toEqual([
    "flags",
    "byProc",
    "byPid",
  ]);
  expect(parsed.unlisted_body_keys).toContain("sharedCache");
  expect(parsed.unlisted_body_keys).not.toContain("osVersion");
  expect(parsed.metadata.unlisted_keys).toContain("slice_uuid");
  expect(parsed.coverage).toEqual({
    status: "complete",
    reason: null,
    threads: 2,
    frames: 5,
    images: 2,
    registers: 6,
    type_mismatches: [],
  });
});

it("assigns frame roles by physical frame depth", () => {
  const roles = (parsed: ReturnType<typeof parse>) =>
    parsed.threads.map((thread) => thread.frames.map((frame) => frame.role));
  expect(roles(report({}))).toEqual([
    ["faulting_instruction", "return_address"],
    // The inlined row shares the sampled program counter with the next row.
    ["current_instruction", "current_instruction", "return_address"],
  ]);
  expect(report({}).threads[1]?.frames[0]?.inline).toBe(true);
  const unknownFault = parse(
    Buffer.from(appleIpsReport().replace('"faultingThread": 0,', ""), "utf8"),
  );
  expect(unknownFault.faulting_thread).toBeNull();
  expect(roles(unknownFault)).toEqual([
    ["unknown", "return_address"],
    ["unknown", "unknown", "return_address"],
  ]);
});

it("classifies SIGKILL codes by canonical hex, not a near-miss decimal", () => {
  const rules = (code: string) =>
    report({ terminationCode: code }).classification.matches;
  expect(rules("3735933132")).toEqual([]);
  expect(rules("3735883980")).toEqual([
    {
      rule: "dead10cc",
      fields: [
        { name: "termination.code", value: "3735883980" },
        { name: "termination.code_hex", value: "0xdead10cc" },
      ],
    },
  ]);
  expect(rules("3221229823").map((row) => row.rule)).toEqual(["thermal"]);
});

it("reports wrong-type collections as partial instead of empty and complete", () => {
  const parsed = parse(
    withBody(
      '{"procName":"x","threads":{"0":{}},"usedImages":"none","exception":{"type":"EXC_CRASH"}}',
    ),
  );
  expect(parsed.threads).toEqual([]);
  expect(parsed.images).toEqual([]);
  expect(parsed.exception?.type).toBe("EXC_CRASH");
  expect(parsed.coverage.status).toBe("partial");
  expect(parsed.coverage.reason).toMatch(/type_mismatches/u);
  expect(parsed.coverage.type_mismatches).toEqual([
    { path: "body.usedImages", expected: "array", observed: "string" },
    { path: "body.threads", expected: "array", observed: "object" },
  ]);
  const absent = parse(withBody('{"procName":"x"}'));
  expect(absent.coverage.type_mismatches).toEqual([
    { path: "body.usedImages", expected: "array", observed: "absent" },
    { path: "body.threads", expected: "array", observed: "absent" },
  ]);
  const empty = parse(withBody('{"threads":[],"usedImages":[]}'));
  expect(empty.coverage.status).toBe("complete");
});

it("records wrong-type rows, scalars and registers with their source path", () => {
  const parsed = parse(
    withBody(`{
      "pid": "4242",
      "osVersion": 15,
      "faultingThread": -1,
      "termination": { "code": 1.5, "reasons": ["ok", 7] },
      "threads": [
        7,
        {
          "frames": [{ "imageIndex": 99999999999, "imageOffset": "8" }, []],
          "threadState": { "flavor": 1, "x": [1, "two", { "value": null }, {}], "rosetta": { "tmp0": 1 } }
        }
      ],
      "usedImages": [null, { "base": 1.0 }]
    }`),
  );
  expect(parsed.process.pid).toBeNull();
  expect(parsed.faulting_thread).toBeNull();
  expect(parsed.termination?.reasons).toEqual(["ok"]);
  expect(parsed.threads).toHaveLength(2);
  expect(parsed.threads[1]?.registers).toEqual([
    { name: "x0", value: { decimal: "1", hex: "0x1" }, description: null },
  ]);
  expect(parsed.images).toHaveLength(2);
  expect(parsed.coverage.status).toBe("partial");
  expect(parsed.coverage.type_mismatches).toEqual([
    { path: "body.usedImages[0]", expected: "object", observed: "null" },
    {
      path: "body.usedImages[1].base",
      expected: "integer",
      observed: "number",
    },
    {
      path: "body.faultingThread",
      expected: "unsigned 32-bit integer",
      observed: "integer out of range",
    },
    { path: "body.threads[0]", expected: "object", observed: "integer" },
    {
      path: "body.threads[1].frames[0].imageIndex",
      expected: "unsigned 32-bit integer",
      observed: "integer out of range",
    },
    {
      path: "body.threads[1].frames[0].imageOffset",
      expected: "integer",
      observed: "string",
    },
    {
      path: "body.threads[1].frames[1]",
      expected: "object",
      observed: "array",
    },
    {
      path: "body.threads[1].threadState.x[1]",
      expected: "integer or object with integer value",
      observed: "string",
    },
    {
      path: "body.threads[1].threadState.x[3].value",
      expected: "integer",
      observed: "absent",
    },
    {
      path: "body.threads[1].threadState.rosetta.value",
      expected: "integer",
      observed: "absent",
    },
    {
      path: "body.threads[1].threadState.flavor",
      expected: "string",
      observed: "integer",
    },
    {
      path: "body.termination.code",
      expected: "integer",
      observed: "number",
    },
    {
      path: "body.termination.reasons[1]",
      expected: "string",
      observed: "integer",
    },
    { path: "body.pid", expected: "integer", observed: "string" },
    {
      path: "body.osVersion",
      expected: "string or object",
      observed: "integer",
    },
  ]);
});

it("refuses invalid UTF-8 instead of replacing bytes", () => {
  const valid = appleIpsBytes({ procName: "rea-é" });
  const offset = valid.indexOf(Buffer.from("é", "utf8"));
  const corrupt = Buffer.from(valid);
  corrupt[offset] = 0xff;
  expect(parse(valid).process.name).toBe("rea-é");
  expect(() => parse(corrupt)).toThrow(
    expect.objectContaining({
      kind: "malformed",
      message: expect.stringMatching(/UTF-8/u),
    }),
  );
});

const registerFlood = (count: number): Buffer =>
  withBody(
    `{"threads":[{"threadState":{"x":[${Array.from({ length: count }, () => "0").join(",")}]}}],"usedImages":[]}`,
  );

it("budgets register slots before expanding threadState rows", () => {
  const flood = registerFlood(150_000);
  expect(flood.length).toBeLessThan(400_000);
  expect(() => parse(flood)).toThrow(
    expect.objectContaining({ boundary: "registers", maximum: 16384 }),
  );
  expect(parse(registerFlood(4), { max_registers: 4 }).coverage.registers).toBe(
    4,
  );
  expect(() => parse(registerFlood(5), { max_registers: 4 })).toThrow(
    AppleIpsResourceFailure,
  );
});

it("refuses an over-budget collection before parsing the rows past the allowance", () => {
  // Rows after the allowance are invalid JSON; the budget must refuse first.
  const threads = withBody(`{"threads":[{},{},{},?],"usedImages":[]}`);
  expect(() => parse(threads, { max_threads: 3 })).toThrow(
    expect.objectContaining({ boundary: "threads", maximum: 3 }),
  );
  const frames = withBody(
    `{"threads":[{"frames":[{},{}]},{"frames":[{},?]}],"usedImages":[]}`,
  );
  expect(() => parse(frames, { max_frames: 3 })).toThrow(
    expect.objectContaining({ boundary: "frames", maximum: 3 }),
  );
  const images = withBody(`{"threads":[],"usedImages":[{},?]}`);
  expect(() => parse(images, { max_images: 1 })).toThrow(
    expect.objectContaining({ boundary: "images", maximum: 1 }),
  );
});

it("skips unconsumed producer members and bounds fixed structural allowances", () => {
  const skipped = parse(
    withBody(
      `{"threads":[],"usedImages":[],"lastExceptionBacktrace":[${Array.from({ length: 100_000 }, () => "{}").join(",")}]}`,
    ),
  );
  expect(skipped.coverage.status).toBe("complete");
  expect(skipped.unlisted_body_keys).toEqual(["lastExceptionBacktrace"]);
  const keys = Array.from(
    { length: 1025 },
    (_, index) => `"k${String(index)}":0`,
  ).join(",");
  expect(() => parse(withBody(`{${keys}}`))).toThrow(
    expect.objectContaining({ boundary: "unlisted_keys", maximum: 1024 }),
  );
  const deep = `${"[".repeat(100)}${"]".repeat(100)}`;
  expect(() => parse(withBody(`{"vmSummary":${deep}}`))).toThrow(
    expect.objectContaining({ boundary: "nesting", maximum: 64 }),
  );
  const reasons = JSON.stringify(Array.from({ length: 257 }, () => "r"));
  expect(() =>
    parse(withBody(`{"termination":{"reasons":${reasons}}}`)),
  ).toThrow(expect.objectContaining({ boundary: "termination_reasons" }));
});
