/**
 * Builds SQL text and its bound parameters together (RES-2). The text comes only from the literal parts of `sql`
 * template literals and from `?` placeholders; every substituted value that is not itself a {@link Sql} becomes a
 * bound parameter, so input is never spliced into the text.
 */

/** The largest number of bound parameters one query may use. The Durable Object SQL API allows 100. */
export const MAX_BOUND_PARAMETERS = 90;

export type SqlValue = string | number | null;

export class Sql {
  readonly text: string;
  readonly params: readonly SqlValue[];

  private constructor(text: string, params: readonly SqlValue[]) {
    this.text = text;
    this.params = params;
  }

  /** `sql` tag: literal parts are text, a substituted {@link Sql} is inlined, any other value is bound as `?`. */
  static template(strings: TemplateStringsArray, ...values: readonly (Sql | SqlValue)[]): Sql {
    let text = strings[0] ?? "";
    const params: SqlValue[] = [];
    values.forEach((value, index) => {
      if (value instanceof Sql) {
        text += value.text;
        params.push(...value.params);
      } else {
        text += "?";
        params.push(value);
      }
      text += strings[index + 1] ?? "";
    });
    return new Sql(text, params);
  }

  /** Joins fragments with a separator fragment. */
  static join(parts: readonly Sql[], separator: Sql): Sql {
    let text = "";
    const params: SqlValue[] = [];
    parts.forEach((part, index) => {
      if (index > 0) {
        text += separator.text;
        params.push(...separator.params);
      }
      text += part.text;
      params.push(...part.params);
    });
    return new Sql(text, params);
  }
}

/** The `sql` tag; see {@link Sql.template}. */
export function sql(strings: TemplateStringsArray, ...values: readonly (Sql | SqlValue)[]): Sql {
  return Sql.template(strings, ...values);
}

/** `?, ?, ?`: one placeholder per value, each value bound. */
export function list(values: readonly SqlValue[]): Sql {
  return Sql.join(
    values.map((value) => sql`${value}`),
    sql`, `,
  );
}
