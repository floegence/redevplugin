const { createRequire } = require("node:module");

const redoclyRequire = createRequire(require.resolve("@redocly/openapi-core/package.json"));
const minimatchPath = redoclyRequire.resolve("minimatch");
const minimatchModule = redoclyRequire(minimatchPath);

if (typeof minimatchModule !== "function") {
  if (typeof minimatchModule?.minimatch !== "function") {
    throw new TypeError("unsupported minimatch export shape for Redocly compatibility");
  }
  const callableMinimatch = Object.assign(
    (...args) => minimatchModule.minimatch(...args),
    minimatchModule,
  );
  require.cache[minimatchPath].exports = callableMinimatch;
}
