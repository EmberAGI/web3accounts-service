import assert from "node:assert";

export function assertIsDefined<T>(
  property: string,
  value: T
): asserts value is NonNullable<T> {
  if (value === undefined || value === null) {
    throw new assert.AssertionError({
      message: `'${property}' is not defined`,
      actual: value,
    });
  }
}
