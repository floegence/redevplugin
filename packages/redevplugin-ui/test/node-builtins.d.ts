declare module "node:assert/strict" {
  const assert: {
    equal(actual: unknown, expected: unknown, message?: string): void;
    deepEqual(actual: unknown, expected: unknown, message?: string): void;
    throws(block: () => unknown, error?: unknown, message?: string): void;
    rejects(block: Promise<unknown> | (() => Promise<unknown>), validator?: (error: unknown) => boolean, message?: string): Promise<void>;
  };
  export default assert;
}

declare module "node:test" {
  export function test(name: string, fn: () => unknown | Promise<unknown>): void;
}
