import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useForm } from 'react-hook-form';
import { Activity, Bell, BellOff, CircleCheck, CircleHelp, CircleX, Clock3, HeartPulse, LoaderCircle, Pencil, Play, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import type { CheckResult, State } from '@/lib/types';
import { formatMs } from '@/lib/utils';
import { getLocale } from '@/lib/i18n';
import { useStorage } from '@/hooks/use-storage';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

const l = (en: string, id: string) => getLocale() === 'id' ? id : en;
interface Endpoint { id: string; name: string; port: number; protocol: 'http' | 'https'; path: string; expectedStatus: number; latencyLimitMs: number; enabled: boolean }
interface EndpointForm { name: string; port: string; protocol: 'http' | 'https'; path: string; expectedStatus: string; latencyLimitMs: string }
interface CheckRecord { id: string; endpointId: string; name: string; at: string; check: CheckResult | null; requestError: string | null; latencyLimitMs: number }
const defaults: EndpointForm = { name: '', port: '', protocol: 'http', path: '/health', expectedStatus: '200', latencyLimitMs: '500' };
const integer = (value: string, min: number, max: number) => /^\d+$/.test(value) && Number(value) >= min && Number(value) <= max;
export function validCheckPath(value: string) {
  if (!value.startsWith('/') || value.startsWith('//') || value.length > 1024 || /[\\#\u0000-\u0020\u007f]/.test(value)) return false;
  try { const decoded = decodeURIComponent(value); return !decoded.startsWith('//') && !/[\\#\u0000-\u0020\u007f]/.test(decoded); } catch { return false; }
}
function validEndpoint(value: unknown): value is Endpoint {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const item = value as Record<string, unknown>;
  return Object.keys(item).length === 8 && ['id', 'name', 'port', 'protocol', 'path', 'expectedStatus', 'latencyLimitMs', 'enabled'].every(key => Object.hasOwn(item, key)) && typeof item.id === 'string' && !!item.id && item.id.length <= 100 && typeof item.name === 'string' && !!item.name.trim() && item.name.length <= 60 && typeof item.port === 'number' && Number.isInteger(item.port) && item.port >= 1 && item.port <= 65535 && (item.protocol === 'http' || item.protocol === 'https') && typeof item.path === 'string' && validCheckPath(item.path) && typeof item.expectedStatus === 'number' && Number.isInteger(item.expectedStatus) && item.expectedStatus >= 100 && item.expectedStatus <= 599 && typeof item.latencyLimitMs === 'number' && Number.isInteger(item.latencyLimitMs) && item.latencyLimitMs >= 1 && item.latencyLimitMs <= 60000 && typeof item.enabled === 'boolean';
}
function readEndpoints(value: unknown): Endpoint[] { const seen = new Set<string>(); return Array.isArray(value) ? value.slice(0, 12).filter((item): item is Endpoint => { if (!validEndpoint(item) || seen.has(item.id)) return false; seen.add(item.id); return true; }) : []; }
function readCheck(value: unknown, endpoint: Endpoint): CheckResult {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid check response.');
  const result = value as Record<string, unknown>;
  if (result.port !== endpoint.port || result.protocol !== endpoint.protocol || result.path !== endpoint.path || result.expectedStatus !== endpoint.expectedStatus || typeof result.healthy !== 'boolean' || typeof result.responseTimeMs !== 'number' || !Number.isFinite(result.responseTimeMs) || result.responseTimeMs < 0 || typeof result.checkedAt !== 'string' || !Number.isFinite(Date.parse(result.checkedAt)) || (result.statusCode !== null && (typeof result.statusCode !== 'number' || !Number.isInteger(result.statusCode) || result.statusCode < 100 || result.statusCode > 599)) || (result.error !== null && typeof result.error !== 'string') || !result.headers || typeof result.headers !== 'object' || Array.isArray(result.headers) || Object.entries(result.headers).some(([key, value]) => key.length > 256 || typeof value !== 'string' || value.length > 4096)) throw new Error('The check API returned an invalid or mismatched result.');
  return { port: endpoint.port, protocol: endpoint.protocol, path: endpoint.path, expectedStatus: endpoint.expectedStatus, statusCode: result.statusCode as number | null, responseTimeMs: result.responseTimeMs, healthy: result.healthy, checkedAt: result.checkedAt, error: result.error as string | null, headers: Object.fromEntries(Object.entries(result.headers).slice(0, 30)) as Record<string, string> };
}
function severity(record: CheckRecord) { return record.requestError ? 'unavailable' : !record.check?.healthy ? 'unhealthy' : record.check.responseTimeMs > record.latencyLimitMs ? 'slow' : 'healthy'; }
function StatusBadge({ record }: { record?: CheckRecord }) { const status = record ? severity(record) : 'pending'; return <Badge variant={status === 'unhealthy' ? 'destructive' : status === 'healthy' ? 'secondary' : 'outline'}>{status === 'healthy' ? <CircleCheck className="size-3" /> : status === 'unhealthy' ? <CircleX className="size-3" /> : status === 'slow' ? <Clock3 className="size-3" /> : <CircleHelp className="size-3" />}{status === 'pending' ? l('Not checked', 'Belum diperiksa') : status === 'healthy' ? l('Healthy', 'Sehat') : status === 'slow' ? l('Slow', 'Lambat') : status === 'unhealthy' ? l('Unhealthy', 'Tidak sehat') : l('Check unavailable', 'Pemeriksaan tidak tersedia')}</Badge>; }

export function Health({ state }: { state: State }) {
  const [stored, setStored] = useStorage<unknown>('portscope.health.endpoints.v1', []);
  const endpoints = useMemo(() => readEndpoints(stored), [stored]);
  const endpointsRef = useRef(endpoints); endpointsRef.current = endpoints;
  const [records, setRecords] = useState<CheckRecord[]>([]);
  const [running, setRunning] = useState(false);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [auto, setAuto] = useState(false);
  const [interval, setIntervalSeconds] = useState('30');
  const [desktop, setDesktop] = useState(false);
  const desktopRef = useRef(desktop); desktopRef.current = desktop;
  const [editing, setEditing] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<Endpoint | null>(null);
  const [error, setError] = useState('');
  const [historyFilter, setHistoryFilter] = useState('all');
  const mounted = useRef(false), busy = useRef(false), runId = useRef(0);
  const controller = useRef<AbortController | null>(null);
  const requestTimer = useRef<number | null>(null);
  const previousAlert = useRef(new Map<string, string>());
  const form = useForm<EndpointForm>({ defaultValues: defaults });
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; runId.current++; controller.current?.abort(); if (requestTimer.current !== null) window.clearTimeout(requestTimer.current); }; }, []);

  const run = useCallback(async (targets: Endpoint[]) => {
    if (!mounted.current || busy.current || !targets.length) return;
    busy.current = true; const generation = ++runId.current;
    setRunning(true); setError('');
    function recordResult(record: CheckRecord) {
      setRecords(previous => { const next = [record, ...previous]; const counts = new Map<string, number>(); return next.filter(item => { const count = (counts.get(item.endpointId) ?? 0) + 1; counts.set(item.endpointId, count); return count <= 20; }).slice(0, 240); });
      const status = severity(record), previous = previousAlert.current.get(record.endpointId);
      previousAlert.current.set(record.endpointId, status);
      if (status === previous) return;
      const message = record.name + ': ' + (status === 'slow' ? l('latency threshold exceeded', 'ambang latensi terlampaui') : status === 'unhealthy' ? l('unexpected status or endpoint failure', 'status tidak sesuai atau endpoint gagal') : status === 'unavailable' ? l('check could not run', 'pemeriksaan tidak dapat dijalankan') : l('check recovered', 'pemeriksaan pulih'));
      if (status === 'healthy') { if (previous) toast.success(message); return; }
      toast.error(message, { description: record.requestError || record.check?.error || (status === 'slow' ? formatMs(record.check?.responseTimeMs) + ' > ' + formatMs(record.latencyLimitMs) : l('Expected HTTP ', 'Diharapkan HTTP ') + record.check?.expectedStatus + ', ' + l('received ', 'diterima ') + (record.check?.statusCode ?? '—')) });
      if (desktopRef.current && 'Notification' in window && Notification.permission === 'granted') { try { new Notification('PortScope · ' + record.name, { body: message, tag: 'portscope-health-' + record.endpointId }); } catch { /* ponytail: some browsers require a service worker; the visible alert and toast remain available. */ } }
    }
    try {
      for (const target of targets) {
        if (!mounted.current || generation !== runId.current) break;
        setActiveId(target.id);
        const aborter = new AbortController(); controller.current = aborter;
        let timedOut = false;
        const timeout = window.setTimeout(() => { timedOut = true; aborter.abort(); }, 6000);
        requestTimer.current = timeout;
        try {
          const response = await fetch('/api/check', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ port: target.port, protocol: target.protocol, path: target.path, expectedStatus: target.expectedStatus }), signal: aborter.signal, cache: 'no-store' });
          const body: unknown = await response.json();
          if (!response.ok || !body || typeof body !== 'object' || !('ok' in body) || body.ok !== true || !('check' in body)) {
            const apiError = body && typeof body === 'object' && 'error' in body ? body.error : null;
            const reason = typeof apiError === 'string' ? apiError : apiError && typeof apiError === 'object' && 'message' in apiError && typeof apiError.message === 'string' ? apiError.message : 'Check API returned HTTP ' + response.status + '.';
            throw new Error(reason);
          }
          const check = readCheck(body.check, target);
          if (!mounted.current || generation !== runId.current) break;
          recordResult({ id: crypto.randomUUID(), endpointId: target.id, name: target.name, at: check.checkedAt, check, requestError: null, latencyLimitMs: target.latencyLimitMs });
        } catch (error) {
          if (!mounted.current || generation !== runId.current) break;
          const message = timedOut ? l('Check API timed out after 6 seconds. Endpoint health is unknown.', 'API pemeriksaan habis waktu 6 detik. Kesehatan endpoint tidak diketahui.') : error instanceof Error ? error.message : l('Could not contact the check API.', 'Tidak dapat menghubungi API pemeriksaan.');
          setError(message);
          recordResult({ id: crypto.randomUUID(), endpointId: target.id, name: target.name, at: new Date().toISOString(), check: null, requestError: message, latencyLimitMs: target.latencyLimitMs });
        } finally { window.clearTimeout(timeout); if (requestTimer.current === timeout) requestTimer.current = null; if (controller.current === aborter) controller.current = null; }
      }
    } finally { if (generation === runId.current) { busy.current = false; if (mounted.current) { setRunning(false); setActiveId(null); } } }
  }, []);
  useEffect(() => {
    if (!auto) return;
    const timer = window.setInterval(() => void run(endpointsRef.current.filter(endpoint => endpoint.enabled)), Number(interval) * 1000);
    return () => window.clearInterval(timer);
  }, [auto, interval, run]);

  async function toggleNotifications() {
    if (desktop) { setDesktop(false); return; }
    if (!('Notification' in window) || !window.isSecureContext) { toast.error(l('Desktop notifications are unavailable in this browser context.', 'Notifikasi desktop tidak tersedia dalam konteks peramban ini.')); return; }
    try { const permission = Notification.permission === 'default' ? await Notification.requestPermission() : Notification.permission; if (!mounted.current) return; setDesktop(permission === 'granted'); if (permission !== 'granted') toast.error(l('Notification permission was not granted. Visible alerts still work.', 'Izin notifikasi tidak diberikan. Peringatan terlihat tetap berfungsi.')); }
    catch { toast.error(l('Could not enable desktop notifications.', 'Tidak dapat mengaktifkan notifikasi desktop.')); }
  }
  function save(values: EndpointForm) {
    if (running) return;
    if (!editing && endpoints.length >= 12) { setError(l('The maximum is 12 endpoint definitions.', 'Maksimal 12 definisi endpoint.')); return; }
    const definition: Endpoint = { id: editing || crypto.randomUUID(), name: values.name.trim(), port: Number(values.port), protocol: values.protocol, path: values.path, expectedStatus: Number(values.expectedStatus), latencyLimitMs: Number(values.latencyLimitMs), enabled: endpoints.find(endpoint => endpoint.id === editing)?.enabled ?? true };
    if (!validEndpoint(definition)) { setError(l('Check the endpoint definition fields.', 'Periksa bidang definisi endpoint.')); return; }
    if (endpoints.some(endpoint => endpoint.id !== definition.id && endpoint.port === definition.port && endpoint.protocol === definition.protocol && endpoint.path === definition.path && endpoint.expectedStatus === definition.expectedStatus)) { form.setError('path', { message: l('This endpoint and expected status are already configured.', 'Endpoint dan status harapan ini sudah dikonfigurasi.') }); return; }
    setStored(editing ? endpoints.map(endpoint => endpoint.id === editing ? definition : endpoint) : [...endpoints, definition]);
    if (editing) { setRecords(previous => previous.filter(record => record.endpointId !== editing)); previousAlert.current.delete(editing); }
    form.reset(defaults); setEditing(null); setError(''); toast.success(l('Endpoint saved locally', 'Endpoint disimpan lokal'));
  }
  const latest = endpoints.map(endpoint => ({ endpoint, record: records.find(record => record.endpointId === endpoint.id) }));
  const alerts = latest.filter(item => item.record && severity(item.record) !== 'healthy');
  const visibleRecords = records.filter(record => historyFilter === 'all' || record.endpointId === historyFilter);
  const storageWarning = !Array.isArray(stored) || stored.length !== endpoints.length;
  return <div className="space-y-5">
    <Alert>
<HeartPulse className="size-4" />
<AlertTitle>{l('Local endpoint checks', 'Pemeriksaan endpoint lokal')}</AlertTitle>
<AlertDescription>{l('A read-only GET is sent by PortScope to loopback only. No external hosts, redirects, credentials or custom headers. Choose endpoints that are safe to GET. Checks and timers stop when you leave this page; this is not an always-on monitoring service.', 'GET baca-saja dikirim PortScope hanya ke loopback. Tanpa host eksternal, pengalihan, kredensial atau header khusus. Pilih endpoint yang aman untuk GET. Pemeriksaan dan timer berhenti ketika meninggalkan halaman ini; bukan layanan pemantauan selalu aktif.')}</AlertDescription>
</Alert>
    {(error || storageWarning) && <Alert variant="destructive">
<AlertTitle>{l('Check notice', 'Pemberitahuan pemeriksaan')}</AlertTitle>
<AlertDescription>{error || l('Invalid browser-local definitions were ignored; they will never be checked automatically.', 'Definisi lokal peramban tidak valid diabaikan; tidak akan diperiksa otomatis.')}</AlertDescription>
</Alert>}
    <div className="grid gap-4 sm:grid-cols-3">
<Card className="gap-2">
<CardHeader>
<CardDescription>{l('Configured endpoints', 'Endpoint dikonfigurasi')}</CardDescription>
<CardTitle className="text-2xl">{endpoints.length}<span className="text-sm font-normal text-muted-foreground"> / 12</span>
</CardTitle>
</CardHeader>
</Card>
<Card className="gap-2">
<CardHeader>
<CardDescription>{l('Latest checks healthy', 'Pemeriksaan terbaru sehat')}</CardDescription>
<CardTitle className="text-2xl">{latest.filter(item => item.record && severity(item.record) === 'healthy').length}<span className="ml-2 text-sm font-normal text-muted-foreground">{l('observed, within threshold', 'teramati, dalam ambang')}</span>
</CardTitle>
</CardHeader>
</Card>
<Card className="gap-2">
<CardHeader>
<CardDescription>{l('Needs attention', 'Perlu perhatian')}</CardDescription>
<CardTitle className="text-2xl">{alerts.length}<span className="ml-2 text-sm font-normal text-muted-foreground">{latest.filter(item => !item.record).length} {l('not checked', 'belum diperiksa')}</span>
</CardTitle>
</CardHeader>
</Card>
</div>
    <Card>
<CardHeader>
<CardTitle>{l('Browser-running schedule', 'Jadwal selama peramban aktif')}</CardTitle>
<CardDescription>{l('Auto-check starts off each visit. Batches run sequentially; overlapping ticks are skipped. Background tabs may be throttled by your browser.', 'Pemeriksaan otomatis dimulai nonaktif setiap kunjungan. Batch berjalan berurutan; tick tumpang tindih dilewati. Tab latar belakang bisa dibatasi peramban.')}</CardDescription>
</CardHeader>
<CardContent>
<div className="flex flex-wrap items-center gap-4">
<div className="flex items-center gap-2">
<Switch id="health-auto" checked={auto} disabled={!auto && !endpoints.some(endpoint => endpoint.enabled)} onCheckedChange={enabled => { setAuto(enabled); if (enabled) void run(endpointsRef.current.filter(endpoint => endpoint.enabled)); }} />
<Label htmlFor="health-auto">{l('Auto-check', 'Periksa otomatis')}</Label>
</div>
<Select value={interval} onValueChange={setIntervalSeconds}>
<SelectTrigger aria-label={l('Auto-check interval', 'Interval pemeriksaan otomatis')} className="w-40">
<SelectValue />
</SelectTrigger>
<SelectContent>{['15', '30', '60'].map(value => <SelectItem key={value} value={value}>{value} {l('seconds', 'detik')}</SelectItem>)}</SelectContent>
</Select>
<Button disabled={running || !endpoints.some(endpoint => endpoint.enabled)} onClick={() => void run(endpoints.filter(endpoint => endpoint.enabled))}>{running ? <LoaderCircle className="size-4 animate-spin" /> : <Play className="size-4" />}{running ? l('Checking…', 'Memeriksa…') : l('Run enabled checks', 'Jalankan pemeriksaan aktif')}</Button>
<Button variant="outline" onClick={() => void toggleNotifications()}>{desktop ? <Bell className="size-4" /> : <BellOff className="size-4" />}{desktop ? l('Desktop alerts on', 'Peringatan desktop aktif') : l('Enable desktop alerts', 'Aktifkan peringatan desktop')}</Button>
<Badge variant="outline">{auto ? l('Page-local schedule active', 'Jadwal lokal halaman aktif') : l('Auto-check stopped', 'Pemeriksaan otomatis berhenti')}</Badge>
</div>
<p className="mt-3 text-xs text-muted-foreground">{l('Disabling auto-check lets the current batch finish. Leaving this page aborts its request and clears all timers. Desktop permission is requested only by the button above; alerts are sent on state transitions, not every polling tick.', 'Menonaktifkan otomatis membiarkan batch berjalan selesai. Meninggalkan halaman membatalkan permintaan dan semua timer. Izin desktop hanya diminta lewat tombol di atas; peringatan dikirim saat perubahan status, bukan setiap tick.')}</p>
</CardContent>
</Card>
    {alerts.length > 0 && <Alert variant="destructive">
<Activity className="size-4" />
<AlertTitle>{l('Latest check alerts', 'Peringatan pemeriksaan terbaru')}</AlertTitle>
<AlertDescription>
<ul className="space-y-1">{alerts.map(({ endpoint, record }) => <li key={endpoint.id}>
<span className="font-medium">{endpoint.name}:</span> {record?.requestError || record?.check?.error || (record && severity(record) === 'slow' ? formatMs(record.check?.responseTimeMs) + ' > ' + formatMs(endpoint.latencyLimitMs) : l('Expected ', 'Diharapkan ') + endpoint.expectedStatus + ', ' + l('received ', 'diterima ') + (record?.check?.statusCode ?? l('no response', 'tanpa respons')))}</li>)}</ul>
</AlertDescription>
</Alert>}
    <Tabs defaultValue="endpoints">
<TabsList>
<TabsTrigger value="endpoints">{l('Endpoints', 'Endpoint')}</TabsTrigger>
<TabsTrigger value="history">{l('Check history', 'Riwayat pemeriksaan')} ({records.length})</TabsTrigger>
</TabsList>
<TabsContent value="endpoints">
<div className="space-y-5">
<Card>
<CardHeader>
<CardTitle>{l('Endpoint definitions', 'Definisi endpoint')}</CardTitle>
<CardDescription>{l('Saved only in this browser. Schedule switches control auto / batch runs; an individual check can always be run manually.', 'Disimpan hanya di peramban ini. Sakelar jadwal mengontrol otomatis/batch; pemeriksaan individu selalu bisa dijalankan manual.')}</CardDescription>
</CardHeader>
<CardContent>
<Table>
<TableHeader>
<TableRow>
<TableHead>{l('Endpoint', 'Endpoint')}</TableHead>
<TableHead>{l('Expected / threshold', 'Harapan / ambang')}</TableHead>
<TableHead>{l('Last result', 'Hasil terakhir')}</TableHead>
<TableHead>{l('Schedule', 'Jadwal')}</TableHead>
<TableHead>{l('Actions', 'Tindakan')}</TableHead>
</TableRow>
</TableHeader>
<TableBody>{latest.map(({ endpoint, record }) => <TableRow key={endpoint.id}>
<TableCell>
<div className="font-medium">{endpoint.name}</div>
<div className="mt-1 max-w-72 break-all whitespace-normal font-mono text-xs text-muted-foreground">{endpoint.protocol}://127.0.0.1:{endpoint.port}{endpoint.path}</div>{!state.ports.some(port => port.port === endpoint.port) && <p className="mt-1 text-xs text-muted-foreground">{l('Not in the latest listener scan', 'Tidak ada di pemindaian listener terakhir')}</p>}</TableCell>
<TableCell>
<span className="font-mono">{endpoint.expectedStatus}</span>
<div className="text-xs text-muted-foreground">≤ {formatMs(endpoint.latencyLimitMs)}</div>
</TableCell>
<TableCell>{activeId === endpoint.id ? <Badge variant="outline">
<LoaderCircle className="size-3 animate-spin" />{l('Checking…', 'Memeriksa…')}</Badge> : <StatusBadge record={record} />}{record && <div className="mt-1 text-xs text-muted-foreground">{record.check && formatMs(record.check.responseTimeMs) + ' · '}{new Date(record.at).toLocaleTimeString()}</div>}</TableCell>
<TableCell>
<Switch checked={endpoint.enabled} disabled={running} aria-label={l('Include in schedule: ', 'Sertakan dalam jadwal: ') + endpoint.name} onCheckedChange={enabled => setStored(endpoints.map(item => item.id === endpoint.id ? { ...item, enabled } : item))} />
</TableCell>
<TableCell>
<div className="flex gap-1">
<Tooltip>
<TooltipTrigger asChild>
<Button variant="ghost" size="icon" disabled={running} aria-label={l('Run check ', 'Jalankan pemeriksaan ') + endpoint.name} onClick={() => void run([endpoint])}>
<Play className="size-4" />
</Button>
</TooltipTrigger>
<TooltipContent>{l('Run once', 'Jalankan sekali')}</TooltipContent>
</Tooltip>
<Button variant="ghost" size="icon" disabled={running} aria-label={l('Edit endpoint ', 'Ubah endpoint ') + endpoint.name} onClick={() => { setEditing(endpoint.id); form.reset({ name: endpoint.name, port: String(endpoint.port), protocol: endpoint.protocol, path: endpoint.path, expectedStatus: String(endpoint.expectedStatus), latencyLimitMs: String(endpoint.latencyLimitMs) }); }}>
<Pencil className="size-4" />
</Button>
<Button variant="ghost" size="icon" disabled={running} aria-label={l('Delete endpoint ', 'Hapus endpoint ') + endpoint.name} onClick={() => setDeleting(endpoint)}>
<Trash2 className="size-4" />
</Button>
</div>
</TableCell>
</TableRow>)}</TableBody>
</Table>{!endpoints.length && <p className="py-12 text-center text-sm text-muted-foreground">{l('No custom checks yet. Add a safe loopback GET endpoint below.', 'Belum ada pemeriksaan khusus. Tambahkan endpoint GET loopback aman di bawah.')}</p>}</CardContent>
</Card>
    <Card>
<CardHeader>
<CardTitle>{editing ? l('Edit endpoint', 'Ubah endpoint') : l('Add endpoint', 'Tambahkan endpoint')}</CardTitle>
<CardDescription>{l('Exact expected HTTP status, plus a separate observed-latency alert threshold. A successful check is not an uptime or request SLO guarantee.', 'Status HTTP harapan tepat, ditambah ambang peringatan latensi teramati terpisah. Pemeriksaan berhasil bukan jaminan uptime atau SLO permintaan.')}</CardDescription>
</CardHeader>
<CardContent>
<Form {...form}>
<form onSubmit={form.handleSubmit(save)} className="space-y-4">
<fieldset disabled={running || !editing && endpoints.length >= 12} className="grid gap-4 sm:grid-cols-2 xl:grid-cols-3">
<FormField control={form.control} name="name" rules={{ required: l('A name is required.', 'Nama wajib diisi.'), maxLength: { value: 60, message: l('Use at most 60 characters.', 'Maksimal 60 karakter.') }, validate: value => !!value.trim() || l('Enter a name.', 'Masukkan nama.') }} render={({ field }) => <FormItem>
<FormLabel>{l('Name', 'Nama')}</FormLabel>
<FormControl>
<Input {...field} placeholder="API health" maxLength={60} />
</FormControl>
<FormMessage />
</FormItem>} />
<FormField control={form.control} name="port" rules={{ validate: value => integer(value, 1, 65535) || l('Use an integer from 1 to 65535.', 'Gunakan bilangan bulat 1–65535.') }} render={({ field }) => <FormItem>
<FormLabel>Port</FormLabel>
<FormControl>
<Input {...field} inputMode="numeric" placeholder="3000" list="health-observed-ports" />
</FormControl>
<datalist id="health-observed-ports">{state.ports.map(port => <option value={port.port} key={port.port}>{port.processName || port.protocol}</option>)}</datalist>
<FormMessage />
</FormItem>} />
<FormField control={form.control} name="protocol" render={({ field }) => <FormItem>
<FormLabel>{l('Protocol', 'Protokol')}</FormLabel>
<Select value={field.value} onValueChange={field.onChange}>
<FormControl>
<SelectTrigger>
<SelectValue />
</SelectTrigger>
</FormControl>
<SelectContent>
<SelectItem value="http">HTTP</SelectItem>
<SelectItem value="https">HTTPS</SelectItem>
</SelectContent>
</Select>
<FormMessage />
</FormItem>} />
<FormField control={form.control} name="path" rules={{ validate: value => validCheckPath(value) || l('Use /path (max 1024), not a URL, //, fragment, backslash or control characters.', 'Gunakan /path (maks. 1024), bukan URL, //, fragmen, backslash atau karakter kontrol.') }} render={({ field }) => <FormItem>
<FormLabel>{l('GET path', 'Path GET')}</FormLabel>
<FormControl>
<Input {...field} placeholder="/health" maxLength={1024} spellCheck={false} />
</FormControl>
<FormDescription>{l('Origin-relative path; loopback host is fixed.', 'Path relatif origin; host loopback tetap.')}</FormDescription>
<FormMessage />
</FormItem>} />
<FormField control={form.control} name="expectedStatus" rules={{ validate: value => integer(value, 100, 599) || l('Use an HTTP status from 100 to 599.', 'Gunakan status HTTP 100–599.') }} render={({ field }) => <FormItem>
<FormLabel>{l('Expected HTTP status', 'Status HTTP harapan')}</FormLabel>
<FormControl>
<Input {...field} inputMode="numeric" />
</FormControl>
<FormMessage />
</FormItem>} />
<FormField control={form.control} name="latencyLimitMs" rules={{ validate: value => integer(value, 1, 60000) || l('Use an integer threshold from 1 to 60000 ms.', 'Gunakan ambang bilangan bulat 1–60000 ms.') }} render={({ field }) => <FormItem>
<FormLabel>{l('Latency threshold (ms)', 'Ambang latensi (ms)')}</FormLabel>
<FormControl>
<Input {...field} inputMode="numeric" />
</FormControl>
<FormMessage />
</FormItem>} />
</fieldset>
<div className="flex gap-2">
<Button type="submit" disabled={running || !editing && endpoints.length >= 12}>
<Plus className="size-4" />{editing ? l('Save changes', 'Simpan perubahan') : l('Add endpoint', 'Tambahkan endpoint')}</Button>{editing && <Button type="button" variant="outline" disabled={running} onClick={() => { setEditing(null); form.reset(defaults); }}>{l('Cancel edit', 'Batal ubah')}</Button>}</div>
</form>
</Form>
</CardContent>
</Card>
</div>
</TabsContent>
    <TabsContent value="history">
<Card>
<CardHeader>
<div className="flex flex-wrap items-center justify-between gap-3">
<div className="space-y-1">
<CardTitle>{l('Observed check results', 'Hasil pemeriksaan teramati')}</CardTitle>
<CardDescription>{l('Last 20 attempts per endpoint, 240 total, kept for this page visit. API failures mean health is unknown, not unhealthy.', '20 percobaan terakhir per endpoint, total 240, disimpan selama kunjungan halaman ini. Kegagalan API berarti kesehatan tidak diketahui, bukan tidak sehat.')}</CardDescription>
</div>
<Select value={historyFilter} onValueChange={setHistoryFilter}>
<SelectTrigger aria-label={l('Filter check history', 'Filter riwayat pemeriksaan')} className="w-52">
<SelectValue />
</SelectTrigger>
<SelectContent>
<SelectItem value="all">{l('All endpoints', 'Semua endpoint')}</SelectItem>{endpoints.map(endpoint => <SelectItem key={endpoint.id} value={endpoint.id}>{endpoint.name}</SelectItem>)}</SelectContent>
</Select>
</div>
</CardHeader>
<CardContent>
<Table>
<TableHeader>
<TableRow>
<TableHead>{l('Endpoint', 'Endpoint')}</TableHead>
<TableHead>{l('Result', 'Hasil')}</TableHead>
<TableHead>HTTP</TableHead>
<TableHead>{l('Observed latency', 'Latensi teramati')}</TableHead>
<TableHead>{l('Checked at', 'Waktu pemeriksaan')}</TableHead>
<TableHead>{l('Detail', 'Detail')}</TableHead>
</TableRow>
</TableHeader>
<TableBody>{visibleRecords.map(record => <TableRow key={record.id}>
<TableCell>{record.name}</TableCell>
<TableCell>
<StatusBadge record={record} />
</TableCell>
<TableCell className="font-mono">{record.check?.statusCode ?? '—'}</TableCell>
<TableCell>{formatMs(record.check?.responseTimeMs)}</TableCell>
<TableCell className="whitespace-nowrap text-xs">{new Date(record.at).toLocaleString()}</TableCell>
<TableCell className="max-w-80 whitespace-normal text-xs text-muted-foreground">{record.requestError || record.check?.error || (severity(record) === 'slow' ? '> ' + formatMs(record.latencyLimitMs) : '—')}</TableCell>
</TableRow>)}</TableBody>
</Table>{!visibleRecords.length && <p className="py-12 text-center text-sm text-muted-foreground">{l('No check attempts recorded here yet. Run a configured endpoint to collect real results.', 'Belum ada percobaan pemeriksaan di sini. Jalankan endpoint untuk mengumpulkan hasil nyata.')}</p>}<Accordion type="multiple" className="mt-4">{latest.filter(item => item.record?.check && Object.keys(item.record.check.headers).length).map(({ endpoint, record }) => <AccordionItem value={endpoint.id} key={endpoint.id}>
<AccordionTrigger>{endpoint.name} · {l('latest response headers', 'header respons terbaru')}</AccordionTrigger>
<AccordionContent>
<Table>
<TableBody>{Object.entries(record!.check!.headers).map(([name, value]) => <TableRow key={name}>
<TableCell className="font-mono text-xs">{name}</TableCell>
<TableCell className="max-w-md break-all whitespace-normal font-mono text-xs">{value}</TableCell>
</TableRow>)}</TableBody>
</Table>
</AccordionContent>
</AccordionItem>)}</Accordion>
</CardContent>
</Card>
</TabsContent>
</Tabs>
    <AlertDialog open={!!deleting} onOpenChange={open => !open && setDeleting(null)}>
<AlertDialogContent>
<AlertDialogHeader>
<AlertDialogTitle>{l('Delete endpoint definition?', 'Hapus definisi endpoint?')}</AlertDialogTitle>
<AlertDialogDescription>{deleting?.name}. {l('This removes its local definition and check history. It does not stop or modify the underlying service.', 'Definisi dan riwayat pemeriksaan lokal dihapus. Layanan yang mendasari tidak dihentikan atau diubah.')}</AlertDialogDescription>
</AlertDialogHeader>
<AlertDialogFooter>
<AlertDialogCancel>{l('Cancel', 'Batal')}</AlertDialogCancel>
<AlertDialogAction disabled={running} onClick={() => { if (!deleting) return; setStored(endpoints.filter(endpoint => endpoint.id !== deleting.id)); setRecords(previous => previous.filter(record => record.endpointId !== deleting.id)); previousAlert.current.delete(deleting.id); if (editing === deleting.id) { setEditing(null); form.reset(defaults); } if (historyFilter === deleting.id) setHistoryFilter('all'); setDeleting(null); }}>{l('Delete endpoint', 'Hapus endpoint')}</AlertDialogAction>
</AlertDialogFooter>
</AlertDialogContent>
</AlertDialog>
  </div>;
}
export function healthSelfCheck() {
  const assert = (condition: unknown) => { if (!condition) throw new Error('Health validation self-check failed.'); };
  assert(validCheckPath('/health') && validCheckPath('/health?ready=1'));
  for (const path of ['https://example.com', '//example.com', '/%2fexample.com', '/bad\\path', '/bad#fragment', '/bad%0d%0a', '/bad path', '/' + 'x'.repeat(1024)]) assert(!validCheckPath(path));
  const definition: Endpoint = { id: 'test', name: 'Test', port: 3000, protocol: 'http', path: '/health', expectedStatus: 200, latencyLimitMs: 500, enabled: true };
  assert(validEndpoint(definition));
  assert(!validEndpoint({ ...definition, port: 0 }) && !validEndpoint({ ...definition, host: 'external.example' }));
  assert(readEndpoints([definition, definition]).length === 1);
  return 'Health path and definition validation checks passed';
}
export default Health;
