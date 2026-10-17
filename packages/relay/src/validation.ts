/**
 * The one bridge from a Valibot schema to the relay's results: a value that matches, or a code of a closed set. The
 * issues Valibot reports can quote the input, so they never leave this function (DATA-1).
 */
import { isHex32 } from "@zenith/core";
import * as v from "valibot";

export type Validated<T, C extends string> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly code: C };

/** Checks `input` against `schema`, stopping at the first issue; any failure is `code`. */
export function validate<const S extends v.GenericSchema, const C extends string>(
  schema: S,
  input: unknown,
  code: C,
): Validated<v.InferOutput<S>, C> {
  const result = v.safeParse(schema, input, { abortEarly: true });
  return result.success ? { ok: true, value: result.output } : { ok: false, code };
}

/** 32 bytes as 64 lowercase hex characters: a public key or a sha256 (`isHex32` of core). */
export const hex32 = v.custom<string>(isHex32);

/** A non-negative safe integer: a unix time, a size or a count. */
export const count = v.pipe(v.number(), v.safeInteger(), v.minValue(0));
