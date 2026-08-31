// 为双产物目录写入 package.json 标记文件。
// 包根 "type": "module",因此 dist/cjs 必须显式声明 commonjs,否则 Node 会按 ESM 解析 .js。
import { writeFileSync, existsSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');

for (const [dir, type] of [
  ['dist/esm', 'module'],
  ['dist/cjs', 'commonjs'],
]) {
  const target = join(root, dir);
  if (!existsSync(target)) {
    throw new Error(`构建产物目录缺失: ${dir}`);
  }
  writeFileSync(join(target, 'package.json'), `${JSON.stringify({ type }, null, 2)}\n`, 'utf8');
}
