export { cn } from 'cn';
export function formatMs(value:number|null|undefined) {return value == null ? '—' : value < 1000 ? Math.round(value) + ' ms' : (value / 1000).toFixed(2) + ' s';}
export function formatAge(ms:number|null|undefined) {if(ms == null) return '—'; const seconds=Math.max(0,Math.floor(ms/1000));return seconds<60 ? seconds+'s' : seconds<3600 ? Math.floor(seconds/60)+'m' : seconds<86400 ? Math.floor(seconds/3600)+'h '+Math.floor(seconds%3600/60)+'m' : Math.floor(seconds/86400)+'d';}
export function download(filename:string,content:string,mime='application/json') {const url=URL.createObjectURL(new Blob([content],{type:mime}));const link=document.createElement('a');link.href=url;link.download=filename;document.body.append(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),1000);}
export async function copyText(text:string) {await navigator.clipboard.writeText(text);}
export function toCsv(rows:unknown[][]) {return rows.map(row=>row.map(value=>{let text=String(value??'');if(/^\s*[=+\-@]/.test(text) || /^[\t\r]/.test(text))text="'"+text;return '"'+text.replaceAll('"','""')+'"';}).join(',')).join('\r\n');}
