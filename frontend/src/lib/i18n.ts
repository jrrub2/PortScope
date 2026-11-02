// Existing five dictionaries; new workspaces explicitly fall back to English.
import * as legacy from './legacy-i18n.js';
export const LANGUAGES: {code:string;name:string}[]=legacy.LANGUAGES;
export const LOCALES:string[]=legacy.LOCALES;
export const getLocale:()=>string=legacy.getLocale;
export const t:(key:string,params?:Record<string,unknown>)=>string=legacy.t;
export const tp=legacy.tp;
export function setLocale(locale:string){const next=legacy.setLocale(locale);legacy.persistLocale(next);return next;}
setLocale(legacy.resolveInitialLocale() || 'en');
