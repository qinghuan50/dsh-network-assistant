import { readdir,readFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { transform } from 'esbuild';
const files=['index.js','client.js'];
async function visit(dir){for(const entry of await readdir(dir,{withFileTypes:true})){const p=`${dir}/${entry.name}`;if(entry.isDirectory())await visit(p);else if(/\.(?:js|jsx|mjs)$/.test(p))files.push(p);}}
await visit('src');await visit('dev');
for(const file of files){const code=await readFile(file,'utf8');const transformed=await transform(code,{loader:file.endsWith('.jsx')?'jsx':'js',target:'node22',sourcefile:file});const result=spawnSync(process.execPath,['--check','--input-type=module'],{input:transformed.code,encoding:'utf8'});if(result.status!==0){process.stderr.write(`${file}\n${result.stderr}`);process.exit(1);}}
console.log(`Syntax checked ${files.length} JavaScript files.`);
