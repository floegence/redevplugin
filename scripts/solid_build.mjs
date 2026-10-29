import { readFile } from "node:fs/promises";
import { transformAsync } from "@babel/core";
import { transform } from "esbuild";
import solid from "babel-preset-solid";

export const solidPlugin = {
  name: "solid-dom",
  setup(build) {
    build.onLoad({ filter: /\.tsx$/ }, async ({ path }) => {
      const source = await readFile(path, "utf8");
      const typescript = await transform(source, { loader: "tsx", jsx: "preserve", target: "es2022", sourcefile: path });
      const result = await transformAsync(typescript.code, { filename: path, presets: [[solid, { generate: "dom", hydratable: false }]], babelrc: false, configFile: false, sourceMaps: false, inputSourceMap: false });
      return { contents: result.code, loader: "js" };
    });
  },
};
