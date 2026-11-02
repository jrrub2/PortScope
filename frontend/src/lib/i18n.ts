import * as legacy from './legacy-i18n.js';
import { UI_TRANSLATIONS } from './ui-translations';
export const LANGUAGES: {code:string;name:string}[]=legacy.LANGUAGES;
export const LOCALES:string[]=legacy.LOCALES;
export const getLocale:()=>string=legacy.getLocale;
export const t:(key:string,params?:Record<string,unknown>)=>string=legacy.t;
export const tp=legacy.tp;
export function setLocale(locale:string){const next=legacy.setLocale(locale);legacy.persistLocale(next);return next;}

export function l(en:string,id:string):string {
  const locale=getLocale();
  if(locale==='en')return en;
  if(locale==='id')return id;
  // ponytail: exact core copy only; extend the table when advanced tools are localized.
  return legacy.translateText(en) ?? UI_TRANSLATIONS[en]?.[locale as 'es'|'ja'|'zh'] ?? en;
}
setLocale(legacy.resolveInitialLocale() || 'en');
