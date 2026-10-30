import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import { parse } from "yaml";
const spec=parse(await readFile(new URL("../spec/openapi/plugin-platform.yaml",import.meta.url),"utf8"));
const fixture=JSON.parse(await readFile(new URL("../spec/plugin/retained-recovery-fixture.json",import.meta.url),"utf8"));
const names=["PluginDataBinding","RetainedRecoveryPlan","RetainedRecoveryResult"];
const defs=Object.fromEntries(names.map(name=>[name,JSON.parse(JSON.stringify(spec.components.schemas[name]).replaceAll("#/components/schemas/","#/$defs/"))]));
const ajv=new Ajv2020({strict:true,validateFormats:false});
for(const [key,name] of [["plan","RetainedRecoveryPlan"],["result","RetainedRecoveryResult"]]){
 test("retained recovery shared "+key+" matches the closed public schema",()=>{
  const validate=ajv.compile({$ref:"#/$defs/"+name,$defs:defs});
  assert.equal(validate(fixture[key]),true,JSON.stringify(validate.errors));
  assert.equal(validate({...fixture[key],owner_env_hash:"foreign"}),false);
  const altered=structuredClone(fixture[key]);
  if(key==="plan")altered.target_management_revision=Number.MAX_SAFE_INTEGER+1;
  else altered.management_revision=0;
  assert.equal(validate(altered),false);
 });
}
test("retained recovery commit is the sole mutation and status is read-only",()=>{
 for(const action of ["inspect","commit","status"]){
  const route=spec.paths["/_redevplugin/api/plugins/retained-data/recovery/"+action].post;
  assert.equal(route["x-redevplugin-route-effect"],action==="commit"?"mutation":"query");
 }
});
