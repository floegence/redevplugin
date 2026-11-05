import assert from 'node:assert/strict';
import {mkdtemp,readFile,writeFile,copyFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join,resolve} from 'node:path';
import {spawn,spawnSync} from 'node:child_process';
import {build} from 'esbuild';
import {chromium} from 'playwright';
const repo=resolve(import.meta.dirname,'..');
assert.ok(['--candidate','--published'].includes(process.argv[2]) && process.argv[3], 'usage: embedding_browser_smoke.mjs --candidate <cli> | --published <version>');
const published=process.argv[2]==='--published';
const version=published?process.argv[3]:(await readFile(join(repo,'VERSION'),'utf8')).trim();
assert.match(version,/^\d+\.\d+\.\d+$/);
const root=await mkdtemp(join(tmpdir(),'redevplugin-embedding-'));
const env={...process.env,GOWORK:'off',GOBIN:root};
const run=(command,args,cwd=root)=>{const result=spawnSync(command,args,{cwd,env,encoding:'utf8',timeout:600000});assert.equal(result.status,0,result.stdout+result.stderr);return result.stdout.trim();};
let child,browser,logs='',exit;
const stop=async()=>{if(child&&child.exitCode===null){child.kill('SIGINT');let timer;try{await Promise.race([exit,new Promise((_,reject)=>{timer=setTimeout(()=>reject(new Error('reference host failed to close')),10000)})])}finally{clearTimeout(timer);if(child.exitCode===null)child.kill('SIGKILL')}}};
try{
 const cli=published?join(root,'redevplugin'):resolve(process.argv[3]);
 const host=join(root,'browser');
 if(published){
  run('go',['install','github.com/floegence/redevplugin/v3/cmd/redevplugin@v'+version]);
  run('go',['install','github.com/floegence/redevplugin/v3/examples/embedding/browser@v'+version]);
 }else run('go',['build','-o',host,'./examples/embedding/browser'],repo);
 await writeFile(join(root,'package.json'),JSON.stringify({private:true,type:'module'}));
 const dependencies=published?['@floegence/redevplugin-contracts@'+version,'@floegence/redevplugin-ui@'+version]:['contracts','ui'].map(name=>run(process.execPath,['scripts/build_redevplugin_'+name+'_package.mjs',version,root],repo));
 run('npm',['install','--ignore-scripts','--no-audit','--no-fund',...dependencies]);
 await copyFile(join(repo,'examples/embedding/browser/parent.ts'),join(root,'parent.ts'));
 await build({entryPoints:[join(root,'parent.ts')],outfile:join(root,'host.js'),bundle:true,format:'esm',platform:'browser',target:'es2022'});
 const project=join(root,'plugin');run(cli,['init','dev.example.reference','Reference document',project,'--template','data']);
 const start=async()=>{
  logs='';child=spawn(host,[join(project,'dist'),join(root,'host.js'),join(root,'state')],{cwd:root,env,stdio:['ignore','pipe','pipe']});
  child.stdout.on('data',data=>logs+=data);child.stderr.on('data',data=>logs+=data);exit=new Promise(done=>child.once('exit',done));
  for(let attempt=0;attempt<150;attempt++){const url=logs.match(/Reference: (http:\/\/localhost:\d+\/#[a-f0-9]+)/u)?.[1];if(url)return url;if(child.exitCode!==null)throw new Error(logs);await new Promise(done=>setTimeout(done,100))}throw new Error('reference host did not start: '+logs);
 };
 browser=await chromium.launch({headless:true});
 const open=async()=>{
  const url=await start();const page=await browser.newPage();await page.goto(url);
  await page.waitForFunction(()=>globalThis.referenceState?.ready||globalThis.referenceState?.error);
  assert.equal(await page.evaluate(()=>globalThis.referenceState.error),'');
  const frames=page.frames().filter(frame=>frame.parentFrame()===page.mainFrame());assert.equal(frames.length,2);
  for(const frame of frames)await frame.getByText('Ready',{exact:true}).waitFor();
  assert.notEqual(new URL(frames[0].url()).origin,new URL(frames[1].url()).origin);
  assert.equal((await fetch(new URL(url).origin+'/bootstrap')).status,403);
  return {page,frames};
 };
 let {page,frames}=await open();
 await frames[0].getByLabel('Document',{exact:true}).fill('persistent independent host');await frames[0].getByRole('button',{name:'Save',exact:true}).click();await frames[0].getByText('Saved',{exact:true}).waitFor();
 const read=await page.evaluate(()=>globalThis.referenceInvoke(1,'application.read',{}));
 const write=await page.evaluate(revision=>globalThis.referenceInvoke(1,'document.replace',{expected_revision:revision,message:'targeted sibling draft'}),read.data.revision);
 assert.equal(write.data.applied,true);assert.equal(await frames[1].getByLabel('Document',{exact:true}).inputValue(),'targeted sibling draft');
 assert.equal(await frames[0].getByLabel('Document',{exact:true}).inputValue(),'persistent independent host');
 await page.evaluate(()=>globalThis.referenceSlots[0].close());assert.equal(await page.locator('iframe').count(),1);
 assert.equal((await page.evaluate(()=>globalThis.referenceInvoke(1,'application.read',{}))).data.message,'targeted sibling draft');
 await page.close();await stop();
 ({page,frames}=await open());
 for(const frame of frames)assert.equal(await frame.getByLabel('Document',{exact:true}).inputValue(),'persistent independent host');
 await page.evaluate(async()=>{for(const slot of globalThis.referenceSlots)await slot.close()});await page.close();
 console.log(JSON.stringify({platform_version:version,artifact_source:published?'public Go and npm registries':'candidate Go and packed npm',worker_runtime:false,checks:['authenticated catalog','SDK sandbox handshake','two independent origins','resource save','targeted Surface method','sibling survives close','persistent data after host restart']}));
}catch(error){throw new Error(String(error)+'\n'+logs,{cause:error})}
finally{if(browser)await browser.close();try{await stop()}finally{await rm(root,{recursive:true,force:true})}}
