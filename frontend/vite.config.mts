import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import tailwindcss from '@tailwindcss/vite';
import { fileURLToPath, URL } from 'node:url';
import { writeFileSync } from 'node:fs';
import { generateNotices } from '../tools/update-notices.mjs';
export default defineConfig({
  root:fileURLToPath(new URL('.',import.meta.url)),
  plugins:[react(),tailwindcss(),{name:'complete-dependency-notices',apply:'build',generateBundle(){const {text}=generateNotices();writeFileSync(fileURLToPath(new URL('./THIRD-PARTY-NOTICES.txt',import.meta.url)),text);this.emitFile({type:'asset',fileName:'THIRD-PARTY-NOTICES.txt',source:text});}}],
  resolve:{alias:{'@':fileURLToPath(new URL('./src',import.meta.url))}},
  build:{outDir:'../web',emptyOutDir:false,assetsDir:'assets'},
});
