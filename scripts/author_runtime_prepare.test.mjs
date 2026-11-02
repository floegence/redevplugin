import assert from "node:assert/strict";
import test from "node:test";
import {mkdtempSync,writeFileSync,rmSync,readFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join,resolve} from "node:path";
import {spawnSync} from "node:child_process";
import Ajv2020 from "ajv/dist/2020.js";
const bundle=resolve("cmd/redevplugin/author_assets/runtime-prepare.mjs");
test("embedded runtime command runs outside a repository and rejects bad requests",()=>{
 const root=mkdtempSync(join(tmpdir(),"author-runtime-test-"));
 try{
  for(const args of [[],["invalid",join(root,"new")],["3.14.0",root]]){
   const result=spawnSync(process.execPath,[bundle,...args],{cwd:root,encoding:"utf8"});
   assert.equal(result.status,1);assert.match(result.stderr,/Expected platform version|Destination already exists/u);assert.doesNotMatch(result.stderr,/Dynamic require|ENOENT/u);
  }
  const marker=join(root,"sentinel");writeFileSync(marker,"retained");
  const result=spawnSync(process.execPath,[bundle,"3.14.0",root],{cwd:root,encoding:"utf8"});
  assert.equal(result.status,1);assert.equal(readFileSync(marker,"utf8"),"retained");
 }finally{rmSync(root,{recursive:true,force:true})}
});
test("author runtime evidence is closed and binds source, toolchain and binary",()=>{
 const validate=new Ajv2020().compile(JSON.parse(readFileSync("spec/plugin/author-development.schema.json","utf8")));
 const digest="a".repeat(64),commit="b".repeat(40);
 const evidence={schema_version:"redevplugin.author-runtime.v1",platform_version:"3.14.0",target:"aarch64-apple-darwin",toolchain:"1.88.0",cargo_version:"cargo 1.88.0",rustc_version:"rustc 1.88.0",source_commit:commit,manifest_sha256:digest,crates:["redevplugin-runtime","redevplugin-worker-sdk"].map(name=>({name,version:"3.14.0",registry_checksum_sha256:digest,source_commit:commit})),binary:"redevplugin-runtime",binary_sha256:digest};
 assert.equal(validate(evidence),true,JSON.stringify(validate.errors));
 assert.equal(validate({...evidence,binary_sha256:"invalid"}),false);
 assert.equal(validate({...evidence,trust:"verified"}),false);
});
