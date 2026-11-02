import assert from "node:assert/strict";
import {readFile} from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import {listCanonicalContractArtifacts} from "./generate_platform_release_manifest.mjs";
test("Surface resource contract rejects authority injection and unbounded control requests",async()=>{
 const schema=JSON.parse(await readFile(new URL("../spec/plugin/surface-resources.schema.json",import.meta.url),"utf8"));
 const fixtures=JSON.parse(await readFile(new URL("../spec/plugin/surface-resources-fixtures.json",import.meta.url),"utf8"));
 const ajv=new Ajv2020({strict:false});ajv.addSchema(schema);const validate=ajv.compile({$ref:schema.$id+"#/$defs/request"});
 for(const fixture of fixtures.valid)assert.equal(validate(fixture),true,JSON.stringify(validate.errors));
 for(const fixture of fixtures.invalid)assert.equal(validate(fixture),false,JSON.stringify(fixture));
 const artifacts=await listCanonicalContractArtifacts();for(const name of ["surface-resources.schema.json","surface-resources-fixtures.json","author-bindings.schema.json"])assert.ok(artifacts.some(a=>a.name==="contract:plugin/"+name));
});
