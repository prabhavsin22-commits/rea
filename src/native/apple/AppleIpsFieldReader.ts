import type {
  AppleIpsTypeMismatch,
  RecordedInteger,
} from "../../domain/native/appleIps.js";
import type { LosslessJson } from "./losslessJson.js";

export type Members = Readonly<Record<string, LosslessJson>>;

const UINT32_MAX = 0xffffffffn;

export const recordedInteger = (decimal: string): RecordedInteger => {
  const value = BigInt(decimal);
  return value < 0n
    ? { decimal, hex: null }
    : { decimal, hex: `0x${value.toString(16)}` };
};

const observedType = (value: LosslessJson | undefined): string =>
  value === undefined
    ? "absent"
    : value.kind === "omitted"
      ? value.type
      : value.kind;

/**
 * Typed field access that records every present value whose JSON type differs
 * from the documented one, so wrong-type input never reads as observed absence.
 * JSON `null` and a missing member both mean "not recorded".
 */
export class FieldReader {
  readonly mismatches: AppleIpsTypeMismatch[] = [];

  mismatch(path: string, expected: string, value: LosslessJson | undefined) {
    this.mismatches.push({ path, expected, observed: observedType(value) });
  }

  text(value: LosslessJson | undefined, path: string): string | null {
    if (value === undefined || value.kind === "null") return null;
    if (value.kind === "string")
      return value.value.length === 0 ? null : value.value;
    this.mismatch(path, "string", value);
    return null;
  }

  integer(
    value: LosslessJson | undefined,
    path: string,
  ): RecordedInteger | null {
    if (value === undefined || value.kind === "null") return null;
    if (value.kind === "integer") return recordedInteger(value.decimal);
    this.mismatch(path, "integer", value);
    return null;
  }

  index(value: LosslessJson | undefined, path: string): number | null {
    if (value?.kind === "integer") {
      const index = BigInt(value.decimal);
      if (index >= 0n && index <= UINT32_MAX) return Number(index);
      this.mismatches.push({
        path,
        expected: "unsigned 32-bit integer",
        observed: "integer out of range",
      });
      return null;
    }
    if (value === undefined || value.kind === "null") return null;
    this.mismatch(path, "unsigned 32-bit integer", value);
    return null;
  }

  boolean(value: LosslessJson | undefined, path: string): boolean | null {
    if (value === undefined || value.kind === "null") return null;
    if (value.kind === "boolean") return value.value;
    this.mismatch(path, "boolean", value);
    return null;
  }

  object(
    value: LosslessJson | undefined,
    path: string,
  ): { members: Members; unlisted: readonly string[] } | null {
    if (value === undefined || value.kind === "null") return null;
    if (value.kind === "object") return value;
    this.mismatch(path, "object", value);
    return null;
  }

  /** An array element is always recorded, so `null` there is a mismatch too. */
  row(value: LosslessJson, path: string): Members {
    if (value.kind === "object") return value.members;
    this.mismatch(path, "object", value);
    return {};
  }

  array(
    value: LosslessJson | undefined,
    path: string,
    required: boolean,
  ): readonly LosslessJson[] | null {
    if (value?.kind === "array") return value.items;
    if (value === undefined || value.kind === "null") {
      if (required) this.mismatch(path, "array", value);
      return null;
    }
    this.mismatch(path, "array", value);
    return null;
  }
}
