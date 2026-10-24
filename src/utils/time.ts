/**
 * @packageDocumentation
 * Time helpers.
 *
 * JWT timestamps are **NumericDate** values
 * (RFC 7519 §2): the
 * number of **seconds** (not milliseconds) since 1970-01-01T00:00:00Z, ignoring
 * leap seconds. `exp`, `nbf`, and `iat` all use this representation.
 *
 * Every timestamp this library reads or writes flows through here so that:
 *  - we consistently work in integer seconds, and
 *  - the clock can be injected in tests, making expiry/`nbf` logic deterministic.
 */

import { InvalidArgumentError } from '../errors.js';

/** A function returning the current time in epoch **milliseconds** (like {@link Date.now}). */
export type Clock = () => number;

/** The default clock, backed by {@link Date.now}. */
export const systemClock: Clock = () => Date.now();

/**
 * Return the current time as an integer **NumericDate** (epoch seconds).
 *
 * @param clock - Millisecond clock to read from; defaults to {@link systemClock}.
 * @returns Whole seconds since the Unix epoch.
 */
export function nowInSeconds(clock: Clock = systemClock): number {
  return Math.floor(clock() / 1000);
}

/**
 * Coerce a `Date` or a numeric epoch-seconds value into an integer NumericDate.
 *
 * @param value - A {@link Date} or a number already expressed in epoch seconds.
 * @returns The value as whole epoch seconds.
 */
export function toNumericDate(value: Date | number): number {
  return value instanceof Date ? Math.floor(value.getTime() / 1000) : Math.floor(value);
}

/** Seconds represented by each supported duration unit, including common long forms. */
const DURATION_UNIT_SECONDS: Readonly<Record<string, number>> = {
  ms: 1 / 1000,
  msec: 1 / 1000,
  msecs: 1 / 1000,
  millisecond: 1 / 1000,
  milliseconds: 1 / 1000,
  s: 1,
  sec: 1,
  secs: 1,
  second: 1,
  seconds: 1,
  m: 60,
  min: 60,
  mins: 60,
  minute: 60,
  minutes: 60,
  h: 3600,
  hr: 3600,
  hrs: 3600,
  hour: 3600,
  hours: 3600,
  d: 86400,
  day: 86400,
  days: 86400,
  w: 604800,
  week: 604800,
  weeks: 604800,
  y: 31557600,
  yr: 31557600,
  yrs: 31557600,
  year: 31557600,
  years: 31557600,
};

/**
 * Parse a human-friendly duration string (e.g. `'1h'`, `'30m'`, `'7d'`) into a
 * whole number of **seconds**. Supported units: `ms`, `s`, `m`, `h`, `d`, `w`,
 * `y`, plus common long forms like `min`, `hours`, `days`. A leading `-` is
 * allowed so a caller can express an already-elapsed span.
 *
 * @param value - The duration string.
 * @returns The duration in whole seconds.
 * @throws {InvalidArgumentError} If the string is not a recognized duration.
 */
export function parseDurationSeconds(value: string): number {
  const match = /^\s*(-?\d+(?:\.\d+)?)\s*([a-zA-Z]+)\s*$/.exec(value);
  const amount = match?.[1];
  const unit = match?.[2];
  if (amount === undefined || unit === undefined) {
    throw new InvalidArgumentError(`invalid duration string: "${value}"`, { context: { value } });
  }
  const perUnitSeconds = DURATION_UNIT_SECONDS[unit.toLowerCase()];
  if (perUnitSeconds === undefined) {
    throw new InvalidArgumentError(`unknown duration unit: "${unit}"`, { context: { value } });
  }
  return Math.floor(Number(amount) * perUnitSeconds);
}

/**
 * Resolve a duration into an absolute NumericDate relative to `from`.
 *
 * Accepts a number of **seconds** (e.g. `3600`), a **duration string** (e.g.
 * `'1h'`), or a `Date`/absolute epoch-seconds — which lets callers write
 * `expiresIn: 3600`, `expiresIn: '1h'`, or `expiresIn: someDate`.
 *
 * @param value - A relative seconds count or duration string, or an absolute `Date`.
 * @param from - The reference instant in epoch seconds (usually "now").
 * @returns The resolved absolute NumericDate.
 * @throws {InvalidArgumentError} If a string value is not a valid duration.
 */
export function resolveTimeClaim(value: number | string | Date, from: number): number {
  if (value instanceof Date) {
    return toNumericDate(value);
  }
  if (typeof value === 'string') {
    return from + parseDurationSeconds(value);
  }
  // A plain number is treated as a relative offset in seconds from `from`.
  return from + Math.floor(value);
}
