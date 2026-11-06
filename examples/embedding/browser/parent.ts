import {PluginPlatformClient, PluginSurfaceSlot, createPluginSurfaceScope, createReDevPluginSurfaceTransport, type FetchLike, type PluginSurfaceHost, type PluginSurfaceContext} from '@floegence/redevplugin-ui/trusted-parent';
const state = {ready:false, error:''};
const slots: PluginSurfaceSlot[] = [];
const surfaces: PluginSurfaceHost[] = [];
let appearanceRevision = 0;
const appearance = (scheme: 'light' | 'dark'): PluginSurfaceContext => ({
 schema_version: 'redevplugin.surface_context.v1', revision: ++appearanceRevision,
 appearance: { color_scheme: scheme, colors: { canvas: scheme === 'dark' ? '#111315' : '#faf9f6', surface: scheme === 'dark' ? '#181b1d' : '#ffffff', surface_elevated: scheme === 'dark' ? '#202426' : '#ffffff', text: scheme === 'dark' ? '#f0f0ed' : '#202322', text_muted: scheme === 'dark' ? '#a0a8a3' : '#69726e', border: scheme === 'dark' ? '#343a36' : '#e1e5e2', accent: '#346653', accent_text: '#ffffff', success: '#21854c', warning: '#ad730f', danger: '#b83d3d', focus: '#478b6b' } },
 locale: { language_tag: 'en-US', direction: 'ltr' },
});
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
  const surface=await client.openSurfaceInSlot(slot,{plugin_instance_id:plugin.plugin_instance_id,surface_id:plugin.manifest.surfaces[0].surface_id,expected_management_revision:plugin.management_revision},{surfaceContext: appearance('light'), onError:error=>{state.error=error.message;}});
  surfaces.push(surface);
  surface.element.style.cssText='display:block;width:100%;height:100%;border:0';
  stage.dataset.surface=surface.surfaceInstanceId;
 }
 Object.assign(globalThis,{referenceInvoke:(index:number,intent_id:string,params:Record<string,never>)=>client.invokeIntent({plugin_instance_id:plugin.plugin_instance_id,surface_instance_id:slots[index].element.dataset.surface,intent_id,params})});
 Object.assign(globalThis,{referenceAppearance:(scheme:'light'|'dark')=>{ for (const surface of surfaces) surface.updateContext(appearance(scheme)); }});
 state.ready=true;document.querySelector('#status')!.textContent='Two independent applications connected';
}catch(error){state.error=String(error);document.querySelector('#status')!.textContent=state.error;}
