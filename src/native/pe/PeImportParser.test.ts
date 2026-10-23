import { createHash } from "node:crypto";
import { expect, it } from "vitest";
import { inspectPeImportsInputSchema } from "../../domain/native/peImports.js";
import {
  peImportFixtureOffset,
  peImportImage,
  peWithoutImportTableFixture,
} from "../../../tests/fixtures/binaryDiagnostics/peImports.js";
import { parsePeImports, PeImportLimitFailure } from "./PeImportParser.js";

const input = inspectPeImportsInputSchema.parse({
  path: "/artifacts/app.exe",
});

const artifact = (bytes: Buffer) => ({
  path: "/artifacts/app.exe",
  sha256: createHash("sha256").update(bytes).digest("hex"),
  bytes: bytes.length,
});

it("reads named PE32+ imports and a pefile-compatible import hash", async () => {
  const bytes = peImportImage({ bits: 64 });
  const report = await parsePeImports(bytes, artifact(bytes), input);
  expect(report.format).toBe("pe32-plus");
  expect(report.bits).toBe(64);
  expect(report.imports).toHaveLength(1);
  expect(report.imports[0]?.name).toBe("KERNEL32.dll");
  expect(report.imports[0]?.functions.map((row) => row.name)).toEqual([
    "GetProcAddress",
    "ExitProcess",
  ]);
  expect(report.imphash.md5).toBe("92cef6cc91a85825f3c8a0516517c66f");
  expect(report.coverage.status).toBe("complete");
  expect(report.delay_imports).toEqual([]);
});

const parse = (bytes: Buffer) => parsePeImports(bytes, artifact(bytes), input);

/** Default PE32+ KERNEL32 image with one descriptor field rewritten. */
const withDescriptorField = async (
  field: number,
  value: number,
  options: Parameters<typeof peImportImage>[0] = {},
) => {
  const bytes = peImportImage(options);
  const location = (await parse(bytes)).imports[0]?.location;
  if (location === undefined) throw new Error("Expected an import descriptor");
  bytes.writeUInt32LE(value, location.offset + field);
  return bytes;
};

it("hashes unmapped ordinals as pefile's ord<decimal> fallback", async () => {
  const bytes = peImportImage({
    bits: 32,
    dlls: [
      {
        name: "USER32.dll",
        functions: [{ ordinal: 42 }],
      },
    ],
  });
  const report = await parsePeImports(bytes, artifact(bytes), input);
  expect(report.format).toBe("pe32");
  expect(report.imports[0]?.functions[0]).toMatchObject({
    name: null,
    ordinal: 42,
    hint: null,
  });
  // pefile 2024.8.26 get_imphash() over this image: MD5("user32.ord42").
  expect(report.imphash).toEqual({
    algorithm: "pefile",
    md5: "f39f7ee67c122319a74d4270d3e5c36c",
    reason: null,
  });
});

it("falls back to ord<decimal> for DLL names that shadow object members", async () => {
  const bytes = peImportImage({
    bits: 32,
    dlls: [
      { name: "constructor", functions: [{ ordinal: 1 }] },
      { name: "__proto__", functions: [{ ordinal: 2 }] },
    ],
  });
  // pefile: "constructor.ord1,__proto__.ord2".
  expect((await parse(bytes)).imphash).toEqual({
    algorithm: "pefile",
    md5: "8a4fd3988e11f8e29b11a7edc60886e6",
    reason: null,
  });
});

it("uses pefile's complete ws2_32 and wsock32 ordinal tables", async () => {
  const bytes = peImportImage({
    bits: 32,
    dlls: [
      {
        name: "WS2_32.dll",
        functions: [{ ordinal: 23 }, { ordinal: 999 }, { name: "WSAStartup" }],
      },
      { name: "wsock32.dll", functions: [{ ordinal: 1155 }, { ordinal: 1 }] },
    ],
  });
  // pefile: "ws2_32.socket,ws2_32.ord999,ws2_32.wsastartup,wsock32.ord1155,wsock32.accept".
  expect((await parse(bytes)).imphash.md5).toBe(
    "79b3bdee998e474e75390fac55093cb0",
  );
});

it("withholds the import hash when a standard import name is unreadable", async () => {
  const bytes = peImportImage();
  const lookup = (await parse(bytes)).imports[0]?.original_first_thunk_rva ?? 0;
  bytes.writeBigUInt64LE(0x7fff0000n, peImportFixtureOffset(lookup + 8));
  const report = await parse(bytes);
  expect(report.imports[0]?.functions.map((row) => row.name)).toEqual([
    "GetProcAddress",
  ]);
  expect(report.issues).toMatchObject([
    { code: "name_unreadable", location: "0x7fff0000" },
  ]);
  expect(report.coverage.status).toBe("partial");
  expect(report.imphash.md5).toBeNull();
  expect(report.imphash.reason).toMatch(/standard import table is incomplete/u);
});

it("withholds the import hash when a standard thunk is unreadable", async () => {
  const bytes = await withDescriptorField(0, 0x7fff0000);
  const report = await parse(bytes);
  expect(report.imports[0]?.functions).toEqual([]);
  expect(report.issues[0]?.code).toBe("thunk_unreadable");
  expect(report.coverage.status).toBe("partial");
  expect(report.imphash.md5).toBeNull();
});

it("reports a zero FirstThunk beside a populated lookup table as malformed", async () => {
  const report = await parse(await withDescriptorField(16, 0));
  expect(report.imports[0]).toMatchObject({
    name: "KERNEL32.dll",
    first_thunk_rva: 0,
    functions: [],
  });
  expect(report.issues).toMatchObject([
    { code: "malformed_entry", message: expect.stringMatching(/FirstThunk/u) },
  ]);
  expect(report.coverage.status).toBe("partial");
  expect(report.imphash.md5).toBeNull();
  expect(report.imphash.reason).toMatch(/incomplete/u);
});

it.each([
  ["import address table", 12],
  ["import name table", 16],
])(
  "reports a delay-load descriptor with a zero %s as malformed without withholding the standard hash",
  async (table, field) => {
    const bytes = peImportImage({
      delayDlls: [
        { name: "ADVAPI32.dll", functions: [{ name: "RegOpenKeyExW" }] },
      ],
    });
    const location = (await parse(bytes)).delay_imports[0]?.location;
    if (location === undefined) throw new Error("Expected a delay descriptor");
    bytes.writeUInt32LE(0, location.offset + field);
    const report = await parse(bytes);
    expect(report.delay_imports[0]?.functions).toEqual([]);
    expect(report.issues).toMatchObject([
      {
        code: "malformed_entry",
        message: expect.stringContaining(`zero ${table} RVA`),
      },
    ]);
    expect(report.coverage.status).toBe("partial");
    expect(report.imphash.md5).toBe("92cef6cc91a85825f3c8a0516517c66f");
  },
);

it("reports each discontiguous file span a descriptor array consumes", async () => {
  const options = {
    delayDlls: [
      { name: "ADVAPI32.dll", functions: [{ name: "RegOpenKeyExW" }] },
    ],
  };
  const whole = await parse(peImportImage(options));
  expect(whole.import_directory?.locations).toEqual([
    { offset: 0x400, bytes: 40 },
  ]);
  expect(whole.delay_import_directory?.locations).toEqual([
    { offset: 0x428, bytes: 64 },
  ]);
  // Second section bytes move to file offset 0x400 + 0x800 + 0x200.
  const importSplit = await parse(peImportImage({ ...options, splitAt: 20 }));
  expect(importSplit.import_directory?.locations).toEqual([
    { offset: 0x400, bytes: 20 },
    { offset: 0xe00, bytes: 20 },
  ]);
  expect(importSplit.delay_import_directory?.locations).toEqual([
    { offset: 0xe14, bytes: 64 },
  ]);
  const delaySplit = await parse(peImportImage({ ...options, splitAt: 72 }));
  expect(delaySplit.import_directory?.locations).toEqual([
    { offset: 0x400, bytes: 40 },
  ]);
  expect(delaySplit.delay_import_directory?.locations).toEqual([
    { offset: 0x428, bytes: 32 },
    { offset: 0xe00, bytes: 32 },
  ]);
  for (const report of [importSplit, delaySplit]) {
    expect(report.coverage.status).toBe("complete");
    expect(report.imports[0]?.functions.map((row) => row.name)).toEqual([
      "GetProcAddress",
      "ExitProcess",
    ]);
    expect(report.delay_imports[0]?.functions[0]?.name).toBe("RegOpenKeyExW");
    expect(report.imphash.md5).toBe("92cef6cc91a85825f3c8a0516517c66f");
  }
});

it.each([
  [
    "a function name pefile treats as invalid",
    { name: "Get-Proc" },
    /invalid/u,
  ],
  ["ordinal 0", { ordinal: 0 }, /ordinal 0/u],
  ["a name pefile truncates", { name: "A".repeat(512) }, /invalid/u],
] as const)(
  "withholds the import hash for %s rather than diverge from pefile",
  async (_label, entry, reason) => {
    const report = await parse(
      peImportImage({
        sectionBytes: 0x1000,
        dlls: [{ name: "KERNEL32.dll", functions: [entry] }],
      }),
    );
    expect(report.coverage.status).toBe("complete");
    expect(report.imphash.md5).toBeNull();
    expect(report.imphash.reason).toMatch(reason);
  },
);

it("reads delay-load descriptors separately from the import hash", async () => {
  const bytes = peImportImage({
    delayDlls: [
      {
        name: "ADVAPI32.dll",
        functions: [{ name: "RegOpenKeyExW", hint: 3 }],
      },
    ],
  });
  const report = await parsePeImports(bytes, artifact(bytes), input);
  expect(report.delay_imports).toHaveLength(1);
  expect(report.delay_imports[0]?.name).toBe("ADVAPI32.dll");
  expect(report.delay_imports[0]?.functions[0]?.name).toBe("RegOpenKeyExW");
  expect(report.imphash.md5).toBe("92cef6cc91a85825f3c8a0516517c66f");
});

it("reports an image without an import directory as importing nothing", async () => {
  const bytes = peWithoutImportTableFixture();
  const report = await parsePeImports(bytes, artifact(bytes), input);
  expect(report.import_directory).toBeNull();
  expect(report.imports).toEqual([]);
  expect(report.coverage.status).toBe("complete");
  expect(report.limitations[0]).toContain(
    "IMAGE_DIRECTORY_ENTRY_IMPORT is absent",
  );
});

it("fails closed when the DLL budget is exhausted", async () => {
  const bytes = peImportImage({
    dlls: [
      { name: "A.dll", functions: [{ name: "a" }] },
      { name: "B.dll", functions: [{ name: "b" }] },
    ],
  });
  await expect(
    parsePeImports(
      bytes,
      artifact(bytes),
      inspectPeImportsInputSchema.parse({
        path: "/artifacts/app.exe",
        max_dlls: 1,
      }),
    ),
  ).rejects.toThrow(
    expect.objectContaining({ limit: "dlls", maximum_bytes: 1 }),
  );
});

it("fails closed when the function budget is exhausted", async () => {
  const bytes = peImportImage({
    dlls: [
      {
        name: "KERNEL32.dll",
        functions: [{ name: "GetProcAddress" }, { name: "ExitProcess" }],
      },
    ],
  });
  await expect(
    parsePeImports(
      bytes,
      artifact(bytes),
      inspectPeImportsInputSchema.parse({
        path: "/artifacts/app.exe",
        max_functions: 1,
      }),
    ),
  ).rejects.toThrow(
    expect.objectContaining({ limit: "functions", maximum_bytes: 1 }),
  );
});

it("fails closed with a structured tag when retained name text is exhausted", async () => {
  const name = "A".repeat(4096);
  const bytes = peImportImage({
    sectionBytes: 0x1200000,
    dlls: [
      {
        name: "KERNEL32.dll",
        functions: Array.from({ length: 4097 }, () => ({ name })),
      },
    ],
  });
  const failure = parse(bytes);
  await expect(failure).rejects.toThrow(PeImportLimitFailure);
  await expect(failure).rejects.toThrow(
    expect.objectContaining({
      limit: "retained_text",
      maximum_bytes: 16 * 1024 * 1024,
    }),
  );
});

it("computes a pefile import hash for oleaut32 ordinal names", async () => {
  const bytes = peImportImage({
    dlls: [
      {
        name: "OLEAUT32.dll",
        functions: [{ ordinal: 2 }],
      },
    ],
  });
  const report = await parsePeImports(bytes, artifact(bytes), input);
  expect(report.imports[0]?.functions[0]).toMatchObject({
    name: null,
    ordinal: 2,
  });
  expect(report.imphash.md5).toBe("3dc76082b322e4bf41120e4657c7f5c6");
});

it("records delay-load virtual-address descriptors as unsupported", async () => {
  const bytes = peImportImage({
    delayDlls: [
      {
        name: "ADVAPI32.dll",
        functions: [{ name: "RegOpenKeyExW" }],
      },
    ],
    delayAttributes: 0,
  });
  const report = await parsePeImports(bytes, artifact(bytes), input);
  expect(report.delay_imports).toEqual([]);
  expect(report.coverage.status).toBe("partial");
  expect(report.issues[0]?.code).toBe("unsupported_form");
  expect(report.imphash.md5).toBe("92cef6cc91a85825f3c8a0516517c66f");
});

it("withholds the import hash exactly where pefile's import symbol cap truncates", async () => {
  const image = (sizes: readonly number[]) =>
    peImportImage({
      sectionBytes: 0x100000,
      dlls: sizes.map((count, dll) => ({
        name: `D${String(dll)}.dll`,
        functions: Array.from({ length: count }, (_, index) => ({
          name: `F${String(dll)}_${String(index)}`,
        })),
      })),
    });
  // pefile 2024.8.26 hashes all 4096 rows here...
  expect((await parse(image([4095, 1]))).imphash.md5).toBe(
    "2217c72699a462a8ca9980afe6a852aa",
  );
  // ...but drops D1.dll here because its 8192-thunk cap is reached first.
  const capped = await parse(image([4096, 1]));
  expect(capped.coverage.status).toBe("complete");
  expect(capped.imphash.md5).toBeNull();
  expect(capped.imphash.reason).toMatch(/descriptor 1 .*symbol cap/u);
});

it("yields during long table walks and stops when the caller cancels", async () => {
  const bytes = peImportImage({
    sectionBytes: 0x20000,
    dlls: [
      {
        name: "KERNEL32.dll",
        functions: Array.from({ length: 4000 }, (_, index) => ({
          name: `F${String(index)}`,
        })),
      },
    ],
  });
  const controller = new AbortController();
  const pending = parsePeImports(
    bytes,
    artifact(bytes),
    input,
    controller.signal,
  );
  let ticks = 0;
  const tick = setImmediate(() => {
    ticks += 1;
    controller.abort();
  });
  await expect(pending).rejects.toMatchObject({
    name: "ArtifactReaderFailure",
    reason: "cancelled",
  });
  clearImmediate(tick);
  expect(ticks).toBe(1);
});

it("withholds the import hash once pefile would discard a repetitive lookup table", async () => {
  const repeated = async (repeats: number) => {
    const bytes = peImportImage({
      dlls: [
        {
          name: "KERNEL32.dll",
          functions: Array.from({ length: repeats + 1 }, (_, index) => ({
            name: `F${String(index)}`,
          })),
        },
      ],
    });
    const lookup = (await parse(bytes)).imports[0]?.original_first_thunk_rva;
    if (lookup === undefined) throw new Error("Expected a lookup table");
    const first = bytes.readBigUInt64LE(peImportFixtureOffset(lookup));
    for (let index = 1; index <= repeats; index++)
      bytes.writeBigUInt64LE(first, peImportFixtureOffset(lookup + index * 8));
    return parse(bytes);
  };
  // pefile 2024.8.26 keeps 14 repeats and hashes the lookup rows...
  expect((await repeated(14)).imphash.md5).toBe(
    "a849c88f8733c2f2171c4130e925bca6",
  );
  // ...but discards the table at 15 and hashes the import address table instead.
  const discarded = await repeated(15);
  expect(discarded.coverage.status).toBe("complete");
  expect(discarded.imphash.md5).toBeNull();
  expect(discarded.imphash.reason).toMatch(/repeats hint\/name addresses 15/u);
});
