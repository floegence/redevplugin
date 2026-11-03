import { gunzipSync } from "node:zlib";
import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync, mkdirSync, rmSync, renameSync, existsSync, realpathSync } from "node:fs";
import { tmpdir, platform, arch } from "node:os";
import { join, resolve } from "node:path";
import { verifyRustRegistryRelease } from "./rust_registry_release.mjs";
import { validateTarGzipArchive } from "./archive_contract.mjs";
import { parseStrictJSON } from "./strict_json.mjs";

const repository = "floegence/redevplugin";
const toolchain = "1.98.0";
const [version, destination] = process.argv.slice(2);
if (!/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u.test(version ?? "") || !destination || process.argv.length !== 4) throw new Error("Expected platform version and destination directory");
const targets = {"darwin-arm64":"aarch64-apple-darwin","darwin-x64":"x86_64-apple-darwin","linux-arm64":"aarch64-unknown-linux-gnu","linux-x64":"x86_64-unknown-linux-gnu"};
const target = targets[platform()+"-"+arch()];
if (!target) throw new Error("Runtime preparation supports Darwin and Linux on arm64 and amd64");
const output = resolve(destination);
if (existsSync(output)) throw new Error("Destination already exists; choose a new build directory");
const temporary = mkdtempSync(join(tmpdir(), "redevplugin-runtime-prepare-"));
const run = (command, args, extra = {}) => execFileSync(command, args, {cwd: temporary, encoding: "utf8", maxBuffer: 4*1024*1024, timeout: 15*60*1000, ...extra});
const hash = bytes => createHash("sha256").update(bytes).digest("hex");
try {
 const tag = "v"+version;
 console.error("Verifying published platform " + tag + " and its GitHub provenance…");
 const sourceCommit = run("gh",["api", "repos/"+repository+"/commits/"+tag,"--jq",".sha"]).trim();
 if (!/^[a-f0-9]{40}$/u.test(sourceCommit)) throw new Error("Invalid release source commit");
 run("gh",["release","download",tag,"--repo",repository,"--pattern","platform-release-manifest.json","--dir",temporary]);
 const manifestPath = join(temporary,"platform-release-manifest.json");
 const manifestBytes = readFileSync(manifestPath);
 const manifest = parseStrictJSON(manifestBytes,"platform release manifest",1024*1024);
 if (Object.keys(manifest).sort().join(",") !== "artifacts,internal_wire,platform_version,plugin_api" || manifest.platform_version !== version || manifest.plugin_api !== 1 || manifest.internal_wire !== 1 || !Array.isArray(manifest.artifacts)) throw new Error("Unexpected platform release contract");
 const names = new Set();
 for (const artifact of manifest.artifacts) {
  if (Object.keys(artifact).sort().join(",") !== "name,sha256" || !/^(go|npm|crate|contract):[^\s=]+$/u.test(artifact.name) || !/^[a-f0-9]{64}$/u.test(artifact.sha256) || names.has(artifact.name)) throw new Error("Invalid platform artifact identity");
  names.add(artifact.name);
 }
 const attestation = run("gh",["attestation","verify",manifestPath,"--repo",repository,"--signer-workflow",repository+"/.github/workflows/release.yml","--source-ref","refs/tags/"+tag,"--source-digest",sourceCommit,"--deny-self-hosted-runners","--format","json"]);
 const crates = await verifyRustRegistryRelease({version,sourceCommit});
 for (const crate of crates) if (manifest.artifacts.find(item=>item.name === "crate:"+crate.name)?.sha256 !== crate.registry_checksum_sha256) throw new Error("Published crate differs from signed platform manifest");
 const coordinate = crates.find(item=>item.name === "redevplugin-runtime");
 const response = await fetch("https://static.crates.io/crates/redevplugin-runtime/redevplugin-runtime-"+version+".crate", {redirect:"error",signal:AbortSignal.timeout(60000)});
 if (!response.ok || Number(response.headers.get("content-length")) > 16*1024*1024) throw new Error("Runtime source download failed");
 const chunks=[]; let received=0;
 for await (const chunk of response.body) { received+=chunk.length; if(received>16*1024*1024) throw new Error("Runtime source exceeds download limit"); chunks.push(chunk); }
 const archive = Buffer.concat(chunks);
 if (archive.length > 16*1024*1024 || hash(archive) !== coordinate.registry_checksum_sha256) throw new Error("Runtime source checksum mismatch");
 const archivePath = join(temporary,"runtime.crate"); writeFileSync(archivePath,archive,{flag:"wx"});
 const sourceName = "redevplugin-runtime-"+version;
 gunzipSync(archive,{maxOutputLength:64*1024*1024});
 validateTarGzipArchive(archivePath,{expectedRoot:sourceName,label:"runtime source"});
 run("tar",["-xzf",archivePath,"-C",temporary]);
 const source = join(temporary,sourceName);
 console.error("Preparing Rust " + toolchain + " and building exact published sources…");
 try { run("rustup",["which","--toolchain",toolchain,"cargo"]); } catch { run("rustup",["toolchain","install",toolchain,"--profile","minimal","--no-self-update"],{stdio:["ignore","inherit","inherit"]}); }
 const cargo = run("rustup",["which","--toolchain",toolchain,"cargo"]).trim();
 const rustc = run("rustup",["which","--toolchain",toolchain,"rustc"]).trim();
 const cargoVersion = run(cargo,["--version"]).trim(), rustcVersion = run(rustc,["--version"]).trim();
 if (!cargoVersion.startsWith("cargo "+toolchain+" ") || !rustcVersion.startsWith("rustc "+toolchain+" ")) throw new Error("Unexpected Rust toolchain identity");
 const cacheBase = process.env.XDG_CACHE_HOME || join(process.env.HOME,".cache");
 const cacheKey = hash(Buffer.from(JSON.stringify({version,target,cargoVersion,rustcVersion,manifest:hash(manifestBytes)})));
 const cache = join(cacheBase,"redevplugin","author-runtime",cacheKey);
 mkdirSync(cache,{recursive:true,mode:0o700});
 const cleanEnvironment = {...process.env};
 for (const key of Object.keys(cleanEnvironment)) if (/^(?:RUSTC|RUSTFLAGS|CARGO_ENCODED_RUSTFLAGS|CARGO_BUILD_|CARGO_TARGET_|CARGO_PROFILE_|CARGO_SOURCE_|CARGO_REGISTRIES_)/u.test(key)) delete cleanEnvironment[key];
 const env = {...cleanEnvironment,RUSTC:rustc,CARGO_TARGET_DIR:join(cache,"target"),CARGO_HOME:join(cache,"cargo"),RUSTFLAGS:"",CARGO_ENCODED_RUSTFLAGS:""};
 // Build only the checksum-verified extracted source, with its released lockfile.
 run(cargo,["build","--release","--locked","--target",target,"--manifest-path",join(source,"Cargo.toml")],{env,stdio:["ignore","inherit","inherit"]});
 const binary = readFileSync(join(cache,"target",target,"release","redevplugin-runtime"));
 const evidence = {schema_version:"redevplugin.author-runtime.v1",platform_version:version,target,toolchain,cargo_version:cargoVersion,rustc_version:rustcVersion,source_commit:sourceCommit,manifest_sha256:hash(manifestBytes),crates,binary:"redevplugin-runtime",binary_sha256:hash(binary)};
 // Publish a complete directory once. A failed preparation never becomes usable.
 const parent = realpathSync(resolve(output,".."));
 const staging = mkdtempSync(join(parent,".redevplugin-runtime-"));
 try {
  writeFileSync(join(staging,"redevplugin-runtime"),binary,{flag:"wx",mode:0o700});
  writeFileSync(join(staging,"evidence.json"),JSON.stringify(evidence,null,2)+"\n",{flag:"wx",mode:0o600});
  writeFileSync(join(staging,"platform-release-manifest.json"),manifestBytes,{flag:"wx",mode:0o600});
  writeFileSync(join(staging,"attestation.json"),attestation,{flag:"wx",mode:0o600});
  if (existsSync(output)) throw new Error("Destination appeared during preparation");
  renameSync(staging,output);
 } finally { rmSync(staging,{recursive:true,force:true}); }
 console.log(JSON.stringify({ok:true,evidence:join(output,"evidence.json"),runtime:join(output,"redevplugin-runtime"),runtime_sha256:evidence.binary_sha256},null,2));
} finally { rmSync(temporary,{recursive:true,force:true}); }
