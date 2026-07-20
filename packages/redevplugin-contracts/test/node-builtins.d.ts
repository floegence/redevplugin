declare module "node:assert/strict" {
  const assert: {
    equal(actual: unknown, expected: unknown, message?: string): void;
    match(actual: string, expected: RegExp, message?: string): void;
    ok(value: unknown, message?: string): asserts value;
    throws(block: () => unknown, error?: unknown, message?: string): void;
  };
  export default assert;
}

declare module "node:test" {
  export function test(name: string, fn: () => unknown | Promise<unknown>): void;
}
