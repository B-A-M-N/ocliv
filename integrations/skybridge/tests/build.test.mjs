import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

// Guards the regression where `skybridge build` typechecked but emitted no
// runnable server entry (`tsc -b` with `noEmit:true`), so `skybridge start`
// failed with ERR_MODULE_NOT_FOUND for dist/index.js.
test('tsconfig emits the server entry to dist/', () => {
  const tsconfig = JSON.parse(readFileSync(new URL('../tsconfig.json', import.meta.url)));
  assert.notEqual(tsconfig.compilerOptions?.noEmit, true, 'tsconfig must emit (noEmit must not be true)');
  assert.equal(tsconfig.compilerOptions?.outDir, 'dist', 'server must compile into dist/');
});
