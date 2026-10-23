import { expect, it } from "vitest";
import {
  BinaryFormatFailure,
  fileMappingLookup,
  mappedFileOffset,
  type FileMapping,
  type ZeroFillMapping,
} from "./BinaryContainer.js";

const outcome = (translate: () => number): number | string => {
  try {
    return translate();
  } catch (cause) {
    // Both scans refuse the same spans; when a span is both an ambiguous file
    // alias and zero-fill overlap, they may name either ambiguity first.
    if (cause instanceof BinaryFormatFailure)
      return /ambiguous/u.test(cause.message) ? "ambiguous" : cause.message;
    throw cause;
  }
};

/** Deterministic xorshift so failures replay exactly. */
const random = (seed: number) => {
  let state = seed;
  return (limit: number): number => {
    state ^= state << 13;
    state ^= state >>> 17;
    state ^= state << 5;
    return (state >>> 0) % limit;
  };
};

it("indexes exactly the spans mappedFileOffset accepts, rejects and translates", () => {
  const next = random(0x5eed);
  const seen = new Set<string>();
  for (let round = 0; round < 150; round++) {
    const mappings: FileMapping[] = Array.from({ length: 1 + next(6) }, () => ({
      address: 0x1000n + BigInt(next(96)),
      offset: next(4) === 0 ? 0x400 : next(256),
      size: next(48),
    }));
    // Some rounds alias one mapping at the same translation to cover consistent overlap.
    if (next(3) === 0 && mappings[0] !== undefined)
      mappings.push({
        address: mappings[0].address + 4n,
        offset: mappings[0].offset + 4,
        size: Math.max(0, mappings[0].size - 4),
      });
    const zeroFills: ZeroFillMapping[] = Array.from(
      { length: next(3) },
      () => ({
        address: 0x1000n + BigInt(next(160)),
        size: BigInt(next(16)),
      }),
    );
    const lookup = fileMappingLookup(mappings, zeroFills);
    const indexed: (number | string)[] = [];
    const scanned: (number | string)[] = [];
    for (let address = 0xff8n; address < 0x10a8n; address++) {
      for (const size of [1, 2, 4, 9, 20]) {
        indexed.push(outcome(() => lookup(address, size)));
        scanned.push(
          outcome(() => mappedFileOffset(mappings, address, size, zeroFills)),
        );
      }
    }
    expect(indexed, `round ${String(round)}`).toEqual(scanned);
    for (const value of scanned)
      seen.add(typeof value === "number" ? "translated" : value);
  }
  expect([...seen].sort()).toEqual([
    "Virtual address or string range is not file mapped",
    "ambiguous",
    "translated",
  ]);
});

it("rejects spans that only adjacent mappings cover together", () => {
  const lookup = fileMappingLookup([
    { address: 0x1000n, offset: 0x400, size: 0x10 },
    { address: 0x1010n, offset: 0x410, size: 0x10 },
  ]);
  expect(lookup(0x1008n, 8)).toBe(0x408);
  expect(() => lookup(0x100cn, 8)).toThrow(/not file mapped/u);
});

it("rejects partially overlapping mappings with different file translations", () => {
  const lookup = fileMappingLookup([
    { address: 0x1000n, offset: 0x400, size: 0x20 },
    { address: 0x1018n, offset: 0x900, size: 0x10 },
  ]);
  expect(lookup(0x1000n, 0x10)).toBe(0x400);
  expect(() => lookup(0x1010n, 0x10)).toThrow(/ambiguous file mappings/u);
});
