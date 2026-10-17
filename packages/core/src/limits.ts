/** Limits applied to every received event. */
export type EventLimits = {
  /** Maximum UTF-8 byte length of the raw event JSON as received. */
  readonly maxEventBytes: number;
  /** Maximum number of tags. */
  readonly maxTags: number;
  /** Maximum UTF-8 byte length of each string inside a tag. */
  readonly maxTagValueBytes: number;
  /** How far `created_at` may be ahead of the current time, in seconds. The past is not limited. */
  readonly maxFutureSeconds: number;
};

export const DEFAULT_EVENT_LIMITS: EventLimits = Object.freeze({
  maxEventBytes: 256 * 1024,
  maxTags: 2000,
  maxTagValueBytes: 1024,
  maxFutureSeconds: 900,
});

/** Limits applied to the filters of a REQ. */
export type FilterLimits = {
  /** Maximum number of filters in one REQ. */
  readonly maxFilters: number;
  /** Upper bound applied to `limit`; also the limit used when a filter has none. */
  readonly maxLimit: number;
  /** Maximum number of values in one filter, summed over ids, authors, kinds and every tag list. */
  readonly maxFilterValues: number;
};

export const DEFAULT_FILTER_LIMITS: FilterLimits = Object.freeze({
  maxFilters: 10,
  maxLimit: 500,
  maxFilterValues: 1000,
});

/** Limits applied to NIP-42 AUTH events. */
export type AuthLimits = {
  /** How far `created_at` may be from the current time, in either direction, in seconds. */
  readonly maxClockSkewSeconds: number;
};

export const DEFAULT_AUTH_LIMITS: AuthLimits = Object.freeze({
  maxClockSkewSeconds: 600,
});
