const fs = require('node:fs');
const path = require('node:path');
const ts = require('typescript');

const cache = new Map();
module.exports = function loadComponent(name) {
  if (cache.has(name)) return cache.get(name);
  const source = fs.readFileSync(path.join(__dirname, '../src/components', name + '.tsx'), 'utf8');
  const compiled = ts.transpileModule(source, {
    compilerOptions: { jsx: ts.JsxEmit.ReactJSX, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const exports = {};
  cache.set(name, exports);
  new Function('require', 'exports', compiled)(
    specifier => specifier.startsWith('./') ? loadComponent(specifier.slice(2)) : require(specifier), exports,
  );
  return exports;
};
