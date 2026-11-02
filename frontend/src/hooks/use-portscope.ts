import { useCallback, useEffect, useRef, useState } from 'react';
import type { State, NetworkSnapshot, HistorySnapshot } from '@/lib/types';
import { useStorage } from './use-storage';
async function getJson(path:string,signal?:AbortSignal) {const response=await fetch(path,{signal:signal?AbortSignal.any([signal,AbortSignal.timeout(10000)]):AbortSignal.timeout(10000),cache:'no-store'});if(!response.ok)throw new Error(path+' · HTTP '+response.status);return response.json();}
function isState(value:unknown):value is State {const s=value as State;return Boolean(s?.ok&&s.meta&&s.stats&&Array.isArray(s.ports)&&Array.isArray(s.events));}
export function usePortScope(){
  const [state,setState]=useState<State|null>(null);
  const [network,setNetwork]=useState<NetworkSnapshot|null>(null);
  const [history,setHistory]=useState<HistorySnapshot|null>(null);
  const [connection,setConnection]=useState<'connecting'|'live'|'polling'|'offline'>('connecting');
  const [error,setError]=useState<string|null>(null);
  const [live,setLive]=useStorage('portscope.live',true);
  const lastFrame=useRef(0),lastNetwork=useRef(0);
  const hydrated=useRef(false),refreshing=useRef(false);
  const accept=useCallback((data:unknown)=>{if(!isState(data))throw new Error('Invalid PortScope state');hydrated.current=true;setState(previous=>previous&&previous.meta.scanCount>data.meta.scanCount?previous:data);setError(null);},[]);
  const acceptNetwork=useCallback((data:NetworkSnapshot)=>{if(!Array.isArray(data?.connections)||!Array.isArray(data.interfaces)||!data.summary)throw new Error('Invalid network snapshot');setNetwork(previous=>previous?.scannedAt&&data.scannedAt&&previous.scannedAt>data.scannedAt?previous:data);},[]);
  const acceptHistory=useCallback((data:HistorySnapshot)=>{if(!Array.isArray(data?.samples))throw new Error('Invalid history snapshot');setHistory(previous=>previous?.samples.at(-1)?.at&&data.samples.at(-1)?.at&&previous.samples.at(-1)!.at>data.samples.at(-1)!.at?previous:data);},[]);
  const refresh=useCallback(async()=>{if(refreshing.current)return;refreshing.current=true;try{const res=await fetch('/api/scan',{method:'POST',signal:AbortSignal.timeout(5000)});if(!res.ok)throw new Error('Scan · HTTP '+res.status);accept(await getJson('/api/state'));const [n,h]=await Promise.all([getJson('/api/network'),getJson('/api/history')]);acceptNetwork(n);acceptHistory(h);}catch(e){setError(e instanceof Error?e.message:String(e));throw e;}finally{refreshing.current=false;}},[accept,acceptNetwork,acceptHistory]);
  useEffect(()=>{
    const controller=new AbortController();let stream:EventSource|null=null,busy=false;
    const poll=async(initial=false)=>{if(busy||controller.signal.aborted)return;busy=true;try{
      if(initial||!lastFrame.current||Date.now()-lastFrame.current>12000){const data=await getJson('/api/state',controller.signal);if(!controller.signal.aborted){accept(data);if(live&&Date.now()-lastFrame.current>12000)setConnection('polling');}}
      if(initial||!lastNetwork.current||Date.now()-lastNetwork.current>12000){const [n,h]=await Promise.all([getJson('/api/network',controller.signal),getJson('/api/history',controller.signal)]);if(!controller.signal.aborted){acceptNetwork(n);acceptHistory(h);}}
    }catch(e){if(!controller.signal.aborted){setError(e instanceof Error?e.message:String(e));if(!lastFrame.current||Date.now()-lastFrame.current>15000)setConnection('offline');}}finally{busy=false;}};
    if(!live){if(!hydrated.current)void poll(true);return()=>controller.abort();}
    setConnection('connecting');lastFrame.current=0;lastNetwork.current=0;void poll(true);
    try{
      stream=new EventSource('/api/stream');
      stream.addEventListener('state',event=>{if(controller.signal.aborted)return;try{accept(JSON.parse((event as MessageEvent).data));lastFrame.current=Date.now();setConnection('live');}catch(e){setError(String(e));}});
      stream.addEventListener('network',event=>{if(controller.signal.aborted)return;try{acceptNetwork(JSON.parse((event as MessageEvent).data));lastNetwork.current=Date.now();}catch(e){setError(String(e));}});
      stream.addEventListener('history',event=>{if(controller.signal.aborted)return;try{acceptHistory(JSON.parse((event as MessageEvent).data));}catch(e){setError(String(e));}});
      stream.onerror=()=>{if(!controller.signal.aborted)setConnection('polling');};
    }catch{setConnection('polling');}
    const timer=setInterval(()=>void poll(),4000);
    return()=>{clearInterval(timer);controller.abort();stream?.close();};
  },[live,accept,acceptNetwork,acceptHistory]);
  return {state,network,history,connection,error,live,setLive,refresh};
}
