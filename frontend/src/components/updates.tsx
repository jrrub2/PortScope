import { useCallback, useEffect, useRef, useState } from 'react';
import { ArrowUpRight, Download, Loader2, RefreshCw, X } from 'lucide-react';
import { toast } from 'sonner';
import { l } from '@/lib/i18n';
import { controlHeaders } from '@/lib/control';
import { useStorage } from '@/hooks/use-storage';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { Switch } from '@/components/ui/switch';

type Release = { version: string; url: string; prerelease: boolean; available: boolean; downloadUrl: string | null; size: number | null; sha256: string | null };
type UpdateStatus = { ok: true; currentVersion: string; portable: boolean; repository: string; releaseUrl: string; update?: Release | null };
const releasesUrl = 'https://github.com/jrrub2/PortScope/releases';
export function readUpdateStatus(value: unknown): UpdateStatus {
  const result = value as UpdateStatus;
  if (!result || result.ok !== true || result.repository !== 'jrrub2/PortScope' || result.releaseUrl !== releasesUrl || typeof result.currentVersion !== 'string' || !/^\d+\.\d+\.\d+$/.test(result.currentVersion) || typeof result.portable !== 'boolean') throw new Error('Invalid update status');
  if (result.update != null) {
    const update = result.update;
    if (typeof update.version !== 'string' || !/^\d+\.\d+\.\d+$/.test(update.version) || update.url !== releasesUrl + '/tag/v' + update.version || typeof update.prerelease !== 'boolean' || typeof update.available !== 'boolean' || (update.downloadUrl !== null && update.downloadUrl !== releasesUrl + '/download/v' + update.version + '/PortScope-' + update.version + '-windows-x64.zip') || (update.sha256 !== null && !/^[a-f0-9]{64}$/.test(update.sha256)) || (update.size !== null && (!Number.isSafeInteger(update.size) || update.size <= 0 || update.size > 150 * 1024 * 1024))) throw new Error('Invalid release');
  }
  return result;
}

export default function Updates({ settings, hidden = false, onSettings }: { settings: boolean; hidden?: boolean; onSettings: () => void }) {
  const [automatic, setAutomatic] = useStorage('portscope.updates.auto', true);
  const [status, setStatus] = useState<UpdateStatus | null>(null), [checked, setChecked] = useState(false);
  const [phase, setPhase] = useState<'idle' | 'check' | 'download' | 'restart'>('idle');
  const [error, setError] = useState<'backend' | 'control' | 'check' | 'download' | 'restart' | null>(null);
  const [dismissed, setDismissed] = useState('');
  const mounted = useRef(false), request = useRef<AbortController | null>(null), phaseRef = useRef(phase), notified = useRef('');
  phaseRef.current = phase;
  const check = useCallback(async (quiet = false) => {
    if (!mounted.current || request.current || phaseRef.current !== 'idle') return;
    const controller = new AbortController(); request.current = controller;
    if (!quiet) { setPhase('check'); setError(null); }
    try {
      const response = await fetch('/api/update/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}', signal: AbortSignal.any([controller.signal, AbortSignal.timeout(20000)]), cache: 'no-store' });
      if (!response.ok) throw new Error(String(response.status));
      const next = readUpdateStatus(await response.json());
      if (!mounted.current || controller.signal.aborted) return;
      setStatus(next); setChecked(true); setError(null);
      if (next.update?.available && notified.current !== next.update.version) {
        notified.current = next.update.version;
        toast.info(l('New version available', 'Versi baru tersedia') + ' · ' + next.update.version, { action: { label: l('Open Settings', 'Buka Pengaturan'), onClick: onSettings }, duration: 12000 });
      }
    } catch { if (!quiet && mounted.current && !controller.signal.aborted) setError('check'); }
    finally { if (request.current === controller) request.current = null; if (!quiet && mounted.current) setPhase('idle'); }
  }, [onSettings]);
  useEffect(() => {
    mounted.current = true;
    const controller = new AbortController();
    void fetch('/api/update/status', { signal: controller.signal, cache: 'no-store' }).then(async response => { if (!response.ok) throw new Error('Unsupported backend'); const next = readUpdateStatus(await response.json()); if (mounted.current && !controller.signal.aborted) setStatus(next); }).catch(() => { if (mounted.current && !controller.signal.aborted) setError('backend'); });
    return () => { mounted.current = false; controller.abort(); request.current?.abort(); request.current = null; };
  }, []);
  useEffect(() => {
    if (!automatic) return;
    const first = window.setTimeout(() => void check(true), 3000);
    const interval = window.setInterval(() => { if (document.visibilityState === 'visible') void check(true); }, 6 * 60 * 60 * 1000);
    return () => { window.clearTimeout(first); window.clearInterval(interval); };
  }, [automatic, check]);
  async function install() {
    const update = status?.update;
    if (!status?.portable || !update?.available || !update.downloadUrl || !update.sha256 || request.current || phaseRef.current !== 'idle') return;
    const controller = new AbortController(); request.current = controller; setPhase('download'); setError(null);
    try {
      const response = await fetch('/api/update/apply', { method: 'POST', headers: { 'Content-Type': 'application/json', ...controlHeaders() }, body: JSON.stringify({ version: update.version, confirm: true }), signal: AbortSignal.any([controller.signal, AbortSignal.timeout(150000)]), cache: 'no-store' });
      const body = await response.json();
      if (!response.ok) { if (mounted.current) setError(body?.error?.code === 'CONTROL_REQUIRED' ? 'control' : 'download'); return; }
      if (body?.ok !== true || body.version !== update.version || body.status !== 'restarting') throw new Error('Unconfirmed update handoff');
      if (!mounted.current || controller.signal.aborted) return;
      setPhase('restart');
      // Keep this origin and browser storage; never accept a redirect URL from release metadata.
      for (let attempt = 0; attempt < 90; attempt++) {
        await new Promise<void>(resolve => { const finish = () => { window.clearTimeout(timer); controller.signal.removeEventListener('abort', finish); resolve(); }; const timer = window.setTimeout(finish, 1000); controller.signal.addEventListener('abort', finish, { once: true }); });
        if (controller.signal.aborted || !mounted.current) return;
        try {
          const health = await fetch('/api/health', { signal: AbortSignal.any([controller.signal, AbortSignal.timeout(2000)]), cache: 'no-store' }).then(response => response.ok ? response.json() : null);
          if (health?.ok === true && health.app === 'PortScope' && health.version === update.version && health.ready === true && health.updateCommitted === true) { toast.success(l('Update installed', 'Pembaruan terpasang')); window.location.reload(); return; }
        } catch { /* The local server is expected to be briefly unavailable during restart. */ }
      }
      if (mounted.current) setError('restart');
    } catch { if (mounted.current && !controller.signal.aborted) setError('restart'); }
    finally { if (request.current === controller) request.current = null; if (mounted.current) setPhase('idle'); }
  }
  const update = status?.update;
  const errorText = error === 'control' ? l('Open the private control link printed in the PortScope console, then try again. Do not share that link.', 'Buka tautan kontrol privat yang tercetak di konsol PortScope, lalu coba lagi. Jangan bagikan tautan tersebut.') : error === 'backend' ? l('The running backend does not support updates yet. Restart PortScope after upgrading it.', 'Backend yang berjalan belum mendukung pembaruan. Mulai ulang PortScope setelah ditingkatkan.') : error === 'check' ? l('Could not check for updates. GitHub may be unavailable or rate-limited. Try again later.', 'Gagal memeriksa pembaruan. GitHub mungkin tidak tersedia atau terkena batas permintaan. Coba lagi nanti.') : error === 'restart' ? l('Restart could not be verified. Keep the portable folder and its update backup; check the launcher console before retrying.', 'Proses mulai ulang belum terverifikasi. Simpan folder portable beserta cadangan pembaruannya; periksa konsol launcher sebelum mencoba lagi.') : l('Update could not be prepared. The current installation has not been replaced.', 'Pembaruan gagal disiapkan. Instalasi saat ini belum diganti.');
  if (!settings) return !hidden && update?.available && dismissed !== update.version ? <Alert data-testid="update-notification" className="border-teal-600/30"><Download className="size-4" /><AlertTitle>{l('New version available', 'Versi baru tersedia')} · {update.version}</AlertTitle><AlertDescription className="flex flex-wrap items-center gap-3"><Button size="sm" variant="outline" onClick={onSettings}>{l('Open Settings', 'Buka Pengaturan')}</Button><Button size="icon" variant="ghost" aria-label={l('Dismiss', 'Tutup')} onClick={() => setDismissed(update.version)}><X className="size-4" /></Button></AlertDescription></Alert> : null;
  return <Card data-testid="update-settings"><CardHeader><CardTitle className="flex items-center gap-2 text-sm"><RefreshCw className="size-4" />{l('Updates', 'Pembaruan')}</CardTitle><CardDescription>{l('Updates come directly from jrrub2/PortScope on GitHub; no separate hosting is needed.', 'Pembaruan diambil langsung dari jrrub2/PortScope di GitHub; tidak memerlukan hosting terpisah.')}</CardDescription></CardHeader><CardContent className="space-y-4">
    <div className="flex flex-wrap items-center justify-between gap-3"><span className="text-xs text-muted-foreground">{l('Current version', 'Versi saat ini')} <span className="font-mono text-foreground">{status?.currentVersion || '—'}</span></span><Button variant="outline" size="sm" disabled={phase !== 'idle'} onClick={() => void check()} data-testid="update-check">{phase === 'check' ? <Loader2 className="size-4 animate-spin" /> : <RefreshCw className="size-4" />}{phase === 'check' ? l('Checking…', 'Memeriksa…') : l('Check for updates', 'Periksa pembaruan')}</Button></div>
    <div className="flex items-center justify-between gap-4"><div className="space-y-1"><Label htmlFor="automatic-update-checks">{l('Automatic update notifications', 'Notifikasi pembaruan otomatis')}</Label><p className="text-xs leading-relaxed text-muted-foreground">{l('Check GitHub when this app opens and every six hours. Updates are never downloaded or installed automatically.', 'Periksa GitHub saat aplikasi dibuka dan setiap enam jam. Pembaruan tidak pernah diunduh atau dipasang otomatis.')}</p></div><Switch id="automatic-update-checks" checked={automatic} onCheckedChange={setAutomatic} disabled={phase === 'download' || phase === 'restart'} /></div>
    {error && <Alert variant="destructive"><AlertDescription role="alert">{errorText}</AlertDescription></Alert>}
    {checked && !update?.available && <p role="status" className="text-sm">{update ? l('You are up to date.', 'Versi Anda sudah terbaru.') : l('No compatible release is available yet.', 'Belum ada rilis yang kompatibel.')}</p>}
    {update?.available && <div className="space-y-3 rounded-md border p-4"><div className="flex flex-wrap items-center gap-2"><p className="text-sm font-semibold">{l('New version available', 'Versi baru tersedia')} · {update.version}</p>{update.prerelease && <Badge variant="outline">{l('Preview release', 'Rilis pratinjau')}</Badge>}</div><p className="text-xs text-muted-foreground">{status?.portable && update.downloadUrl && update.sha256 ? l('Close any important work first. PortScope will restart on the same local address and preserve browser data.', 'Simpan pekerjaan penting terlebih dahulu. PortScope akan dimulai ulang pada alamat lokal yang sama dan mempertahankan data browser.') : l('This installation cannot update itself. Download a newer portable release manually; source files will not be overwritten.', 'Instalasi ini tidak dapat memperbarui dirinya. Unduh rilis portable terbaru secara manual; berkas source tidak akan ditimpa.')}</p><div className="flex flex-wrap gap-2">{status?.portable && update.downloadUrl && update.sha256 && <Button size="sm" onClick={() => void install()} disabled={phase !== 'idle'} data-testid="update-install">{phase === 'download' || phase === 'restart' ? <Loader2 className="size-4 animate-spin" /> : <Download className="size-4" />}{phase === 'download' ? l('Downloading and verifying…', 'Mengunduh dan memverifikasi…') : phase === 'restart' ? l('Restarting PortScope…', 'Memulai ulang PortScope…') : l('Install update', 'Pasang pembaruan')}</Button>}<Button variant="outline" size="sm" asChild><a href={update.url} target="_blank" rel="noopener noreferrer">{l('View release', 'Lihat rilis')}<ArrowUpRight className="size-4" /></a></Button></div></div>}
    <a href={releasesUrl} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-muted-foreground underline underline-offset-4">GitHub Releases<ArrowUpRight className="size-3" /></a>
  </CardContent></Card>;
}
