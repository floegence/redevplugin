import assert from "node:assert/strict";
import {mkdtemp,readFile,writeFile,copyFile,mkdir,rm} from "node:fs/promises";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {spawnSync} from "node:child_process";
const root=resolve(import.meta.dirname,"..");const cli=resolve(process.argv[2]??"dist/author-cli");
const temp=await mkdtemp(join(tmpdir(),"redevplugin-bindings-"));
function run(command,args,cwd){const result=spawnSync(command,args,{cwd,encoding:"utf8",timeout:120000});assert.equal(result.status,0,result.stdout+result.stderr);return result.stdout}
try{
 for(const template of ["web","data","worker","monitor","files"]){const project=join(temp,template);run(cli,["init","dev-example-"+template,"Typed Application",project,"--template",template],root);
 const config=JSON.parse(await readFile(join(project,"tsconfig.json"),"utf8"));config.compilerOptions.paths={"@floegence/redevplugin-ui/plugin":[join(root,"packages/redevplugin-ui/src/plugin.ts")]};await writeFile(join(project,"tsconfig.json"),JSON.stringify(config));run(process.execPath,[join(root,"node_modules/typescript/bin/tsc"),"-p",join(project,"tsconfig.json")],root);
 if(template==="worker"){
  const cargo=join(temp,"rust");await mkdir(join(cargo,"src"),{recursive:true});await copyFile(join(project,"generated/actions.rs"),join(cargo,"src/lib.rs"));
  // The generator is tested against its own SDK source, within this platform repository's test closure.
  await writeFile(join(cargo,"Cargo.toml"),'[package]\nname="author-bindings-compile"\nversion="0.0.0"\nedition="2024"\n[dependencies]\nredevplugin-worker-sdk={path='+JSON.stringify(join(root,"crates/redevplugin-worker-sdk"))+'}\nserde={version="1",features=["derive"]}\nserde_json="1"\n');
  run("cargo",["check","--manifest-path",join(cargo,"Cargo.toml"),"--target-dir",join(root,"target/author-bindings")],root);
 }
 }
 console.log("Generated TypeScript clients and Rust DTO/dispatcher compile successfully.");
}finally{await rm(temp,{recursive:true,force:true})}
