import {PluginPlatformClient, PluginSurfaceSlot, createPluginSurfaceScope, createReDevPluginSurfaceTransport, type FetchLike} from '@floegence/redevplugin-ui/trusted-parent';
const state = {ready:false, error:''};
const slots: PluginSurfaceSlot[] = [];
Object.assign(globalThis,{referenceState:state,referenceSlots:slots});
try {
 const token=location.hash.slice(1);history.replaceState(null,'','/');
 const auth=await fetch('/session',{method:'POST',body:token});if(!auth.ok)throw new Error('Reference session rejected');
 const response=await fetch('/bootstrap');if(!response.ok)throw new Error('Reference bootstrap rejected');
 const bootstrap=await response.json();
 const authenticated:FetchLike=(input,init)=>fetch(input,{...init,headers:{...init.headers,'X-ReDevPlugin-CSRF':bootstrap.csrf}});
 const client=new PluginPlatformClient({fetch:authenticated,surfaceScope:createPluginSurfaceScope(),surfaceTransport:createReDevPluginSurfaceTransport({fetch:authenticated})});
 const catalog=await client.catalog();const plugin=catalog.plugins[0];if(!plugin)throw new Error('Installed plugin missing');
 for(let index=0;index<2;index++){
  const stage=document.createElement('section');stage.style.cssText='display:inline-block;width:48%;height:600px';document.querySelector('#surfaces')!.append(stage);
  const slot=PluginSurfaceSlot.create({stage});slots.push(slot);
  const surface=await client.openSurfaceInSlot(slot,{plugin_instance_id:plugin.plugin_instance_id,surface_id:plugin.manifest.surfaces[0].surface_id,expected_management_revision:plugin.management_revision},{onError:error=>{state.error=error.message;}});
  stage.dataset.surface=surface.surfaceInstanceId;
 }
 Object.assign(globalThis,{referenceInvoke:(index:number,intent_id:string,params:Record<string,never>)=>client.invokeIntent({plugin_instance_id:plugin.plugin_instance_id,surface_instance_id:slots[index].element.dataset.surface,intent_id,params})});
 state.ready=true;document.querySelector('#status')!.textContent='Two independent applications connected';
}catch(error){state.error=String(error);document.querySelector('#status')!.textContent=state.error;}
