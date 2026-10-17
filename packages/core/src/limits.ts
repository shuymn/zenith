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
