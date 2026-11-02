import { useState, useCallback, type SetStateAction } from 'react';
import { toast } from 'sonner';
export function useStorage<T>(key:string,initial:T):[T,(action:SetStateAction<T>)=>void] {
  const [value,setValue]=useState<T>(()=>{try {const saved=localStorage.getItem(key);if(saved===null)return initial;try{const parsed=JSON.parse(saved);if(Array.isArray(initial)&&!Array.isArray(parsed)){toast.warning('Invalid saved preference: '+key+'. It has not been overwritten.');return initial;}if(initial!==null&&typeof parsed!==typeof initial)return initial;return parsed as T;}catch{return (typeof initial==='string'?saved:initial) as T;}}catch{return initial;}});
  const persist=useCallback((action:SetStateAction<T>)=>setValue(previous=>{const next=typeof action==='function'?(action as (v:T)=>T)(previous):action;try{localStorage.setItem(key,JSON.stringify(next));}catch{toast.error('Browser storage unavailable. Changes are kept only in this tab.');}return next;}),[key]);
  return [value,persist];
}
