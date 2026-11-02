import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { useForm } from 'react-hook-form';
import { ArrowDownToLine, Copy, Globe, LoaderCircle, Network, Play, ShieldCheck, Square, TriangleAlert } from 'lucide-react';
import { toast } from 'sonner';
import type { DnsConfig, DnsResponse } from '@/lib/types';
import { copyText, download, formatMs, toCsv } from '@/lib/utils';
import { getLocale } from '@/lib/i18n';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty';
import { Form, FormControl, FormDescription, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

const l = (en: string, id: string) => getLocale() === 'id' ? id : en;
const recordTypes = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS', 'SOA', 'CAA', 'PTR'];
type Mode = DnsResponse['mode'];
interface DnsForm { name: string; servers: string; types: string[] }
interface DnsSpec { mode: Mode; name?: string; types?: string[]; servers?: string[] }
export function dnsNumericIp(value: string) {
  if (/^\d+(?:\.\d+){3}$/.test(value)) return value.split('.').every(part => /^(?:0|[1-9]\d{0,2})$/.test(part) && Number(part) <= 255);
  if (!value.includes(':') || /[%\[\]]/.test(value)) return false;
  try { return new URL('http://[' + value + ']/').hostname.startsWith('['); } catch { return false; }
}
export function parseDnsServers(value: string) {
  const servers = value.trim() ? value.trim().split(/[\s,]+/).filter(Boolean) : [];
  if (servers.length > 3 || new Set(servers).size !== servers.length) throw new Error('Use at most three distinct numeric resolver addresses.');
  for (const server of servers) {
    if (dnsNumericIp(server)) continue;
    const bracketed = /^\[([^\]]+)\]:(\d+)$/.exec(server), ipv4 = /^([^:]+):(\d+)$/.exec(server);
    const match = bracketed || ipv4;
    if (!match || !dnsNumericIp(match[1]) || !/^\d+$/.test(match[2]) || Number(match[2]) < 1 || Number(match[2]) > 65535) throw new Error('Use numeric IPv4, IPv6, IPv4:port or [IPv6]:port (ports 1–65535), not resolver URLs or hostnames.');
  }
  return servers;
}
export function validDnsName(value: string, reverse = false) {
  if (reverse) return dnsNumericIp(value);
  if (!value || value.length > 253 || /[\s/\\@?#%:]/.test(value)) return false;
  return value.replace(/\.$/, '').split('.').every(label => label.length > 0 && label.length <= 63 && /^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?$/i.test(label));
}
function apiMessage(body: unknown, fallback: string) { const error = body && typeof body === 'object' && 'error' in body ? body.error : null; return typeof error === 'string' ? error : error && typeof error === 'object' && 'message' in error && typeof error.message === 'string' ? error.message : fallback; }
function readDns(value: unknown): DnsResponse {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid DNS API response.');
  const result = value as Partial<DnsResponse>;
  if (result.ok !== true || result.source !== 'backend' || !['records', 'compare', 'dnssec', 'reverse'].includes(String(result.mode)) || typeof result.checkedAt !== 'string' || !Number.isFinite(Date.parse(result.checkedAt)) || !Array.isArray(result.results) || result.results.length > 24 || result.results.some(row => !row || typeof row.server !== 'string' || typeof row.type !== 'string' || !['answer', 'nodata', 'error'].includes(row.status) || !Array.isArray(row.answers) || typeof row.durationMs !== 'number' || !Number.isFinite(row.durationMs))) throw new Error('Malformed DNS result.');
  return result as DnsResponse;
}
const answer = (value: unknown) => typeof value === 'string' ? value : JSON.stringify(value, null, 2) ?? 'null';
export function dnsComparisonSignature(value: unknown): string { function canonical(item: unknown): string { if (Array.isArray(item)) return '[' + item.map(canonical).join(',') + ']'; if (item && typeof item === 'object') return '{' + Object.entries(item).filter(([key]) => key !== 'ttl').sort(([a], [b]) => a.localeCompare(b)).map(([key, entry]) => JSON.stringify(key) + ':' + canonical(entry)).join(',') + '}'; return JSON.stringify(item) ?? 'null'; } return Array.isArray(value) ? '[' + value.map(canonical).sort().join(',') + ']' : canonical(value); }

export function DnsTools({ live, children }: { live: boolean; children?: ReactNode }) {
  const [mode, setMode] = useState<Mode>('records');
  const [config, setConfig] = useState<DnsConfig | null>(null), [configError, setConfigError] = useState('');
  const [result, setResult] = useState<DnsResponse | null>(null), [requestError, setRequestError] = useState('');
  const [running, setRunning] = useState(false), [scheduled, setScheduled] = useState(false), [interval, setIntervalSeconds] = useState('30');
  const [attemptedAt, setAttemptedAt] = useState<string | null>(null);
  const mounted = useRef(false), liveRef = useRef(live); liveRef.current = live;
  const controller = useRef<AbortController | null>(null), timer = useRef<number | null>(null), busy = useRef(false), generation = useRef(0);
  const scheduleSpec = useRef<DnsSpec | null>(null), scheduledRef = useRef(false);
  const form = useForm<DnsForm>({ shouldUnregister: true, defaultValues: { name: '', servers: '', types: ['A', 'AAAA'] } });
  const halt = useCallback(() => { scheduledRef.current = false; scheduleSpec.current = null; generation.current++; controller.current?.abort(); if (timer.current !== null) window.clearTimeout(timer.current); timer.current = null; if (mounted.current) setScheduled(false); }, []);
  useEffect(() => {
    mounted.current = true; const aborter = new AbortController();
    fetch('/api/dns/config', { signal: aborter.signal, cache: 'no-store' }).then(async response => { const body: unknown = await response.json(); if (!response.ok || !body || typeof body !== 'object' || !('servers' in body) || !Array.isArray(body.servers) || body.servers.some(server => typeof server !== 'string') || !('ok' in body) || body.ok !== true) throw new Error(apiMessage(body, 'Resolver configuration unavailable.')); if (mounted.current) setConfig(body as DnsConfig); }).catch(error => { if (!aborter.signal.aborted && mounted.current) setConfigError(error instanceof Error ? error.message : 'Resolver configuration unavailable.'); });
    return () => { mounted.current = false; aborter.abort(); halt(); };
  }, [halt]);
  useEffect(() => { if (!live) halt(); }, [live, halt]);
  const run = useCallback(async (spec: DnsSpec) => {
    if (!mounted.current || !liveRef.current || busy.current) return;
    busy.current = true; const runId = ++generation.current; const aborter = new AbortController(); controller.current = aborter;
    const timeout = window.setTimeout(() => aborter.abort(), 12000); timer.current = timeout;
    setRunning(true); setRequestError(''); setAttemptedAt(new Date().toISOString());
    try {
      const response = await fetch('/api/dns', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(spec), signal: aborter.signal, cache: 'no-store' });
      const body: unknown = await response.json(); if (!response.ok) throw new Error(apiMessage(body, 'DNS API returned HTTP ' + response.status + '.'));
      const next = readDns(body); if (next.mode !== spec.mode) throw new Error('Mismatched DNS result mode.');
      if (mounted.current && generation.current === runId) setResult(next);
    } catch (error) { if (mounted.current && generation.current === runId) { setRequestError(aborter.signal.aborted ? l('DNS request timed out. No result was substituted; any previous result is older.', 'Permintaan DNS habis waktu. Hasil tidak diganti; hasil sebelumnya lebih lama.') : error instanceof Error ? error.message : 'DNS request failed.'); toast.error(l('DNS check did not complete', 'Pemeriksaan DNS tidak selesai')); } }
    finally { window.clearTimeout(timeout); if (timer.current === timeout) timer.current = null; if (controller.current === aborter) controller.current = null; busy.current = false; if (mounted.current) setRunning(false); }
  }, []);
  useEffect(() => { if (!scheduled) return; const id = window.setInterval(() => { if (scheduledRef.current && scheduleSpec.current) void run(scheduleSpec.current); }, Number(interval) * 1000); return () => window.clearInterval(id); }, [scheduled, interval, run]);
  function makeSpec(values: DnsForm): DnsSpec { const servers = parseDnsServers(values.servers); if (['records', 'compare'].includes(mode) && values.types.length * (servers.length || Math.min(config?.servers.length || 1, 3)) > 24) throw new Error(l('Reduce record types or resolvers: a run allows at most 24 queries.', 'Kurangi jenis record atau resolver: maksimal 24 kueri per proses.')); return { mode, ...(mode !== 'dnssec' ? { name: values.name.trim() } : {}), ...(['records', 'compare'].includes(mode) ? { types: values.types } : {}), ...(servers.length ? { servers } : {}) }; }
  function submit(values: DnsForm) { if (!live || busy.current) return; try { const spec = makeSpec(values); if (scheduledRef.current) scheduleSpec.current = spec; void run(spec); } catch (error) { form.setError('servers', { message: error instanceof Error ? error.message : 'Invalid resolver addresses.' }); } }
  async function startSchedule() { if (!await form.trigger() || !liveRef.current) return; try { const spec = makeSpec(form.getValues()); scheduleSpec.current = spec; scheduledRef.current = true; setScheduled(true); void run(spec); } catch (error) { form.setError('servers', { message: error instanceof Error ? error.message : 'Invalid resolver addresses.' }); } }
  const copy = async (text: string) => { try { await copyText(text); toast.success(l('Copied resolver address', 'Alamat resolver disalin')); } catch { toast.error(l('Clipboard access failed', 'Akses papan klip gagal')); } };
  const servers = result ? Array.from(new Set(result.results.map(row => row.server))) : [];
  const comparable = result?.mode === 'compare' ? Array.from(new Set(result.results.map(row => row.type))).map(type => { const rows = result.results.filter(row => row.type === type); return { type, complete: rows.length >= 2 && rows.every(row => row.status !== 'error'), agree: new Set(rows.map(row => row.status + ':' + dnsComparisonSignature(row.answers))).size === 1 }; }) : [];
  const dnssec = result?.dnssec;
  return <div className="space-y-5">
    <Alert>
<Globe className="size-4" />
<AlertTitle>{l('DNS checks from the backend host', 'Pemeriksaan DNS dari host backend')}</AlertTitle>
<AlertDescription>{l('These queries are made by Node on the PortScope host using system or explicitly chosen numeric resolvers. They do not reveal your browser DNS, encrypted DNS (DoH), VPN egress or DNS leaks. Run authorizes DNS network traffic; no queries run on page visit.', 'Kueri dibuat Node di host PortScope memakai resolver sistem atau resolver numerik pilihan. Ini tidak mengungkap DNS peramban, DNS terenkripsi (DoH), egress VPN atau kebocoran DNS. Run mengizinkan trafik DNS; tidak ada kueri saat halaman dibuka.')}</AlertDescription>
</Alert>
    <div className="grid gap-4 md:grid-cols-2">
<Card>
<CardHeader>
<CardTitle className="flex items-center gap-2">
<Network className="size-4" />{l('Configured host resolvers', 'Resolver host dikonfigurasi')}</CardTitle>
<CardDescription>{config?.source || l('Node backend resolver configuration', 'Konfigurasi resolver backend Node')}</CardDescription>
</CardHeader>
<CardContent>{configError ? <p className="text-sm text-destructive">{configError}</p> : !config ? <p className="text-sm text-muted-foreground">{l('Reading local configuration…', 'Membaca konfigurasi lokal…')}</p> : <div className="space-y-2">{config.servers.map(server => <div key={server} className="flex items-center justify-between gap-3 rounded-md border px-3 py-2">
<span className="break-all font-mono text-xs">{server}</span>
<Button variant="ghost" size="icon" className="size-7" aria-label={l('Copy resolver ', 'Salin resolver ') + server} onClick={() => void copy(server)}>
<Copy className="size-3" />
</Button>
</div>)}{!config.servers.length && <p className="text-sm text-muted-foreground">{l('The backend reported no configured resolver addresses.', 'Backend tidak melaporkan alamat resolver dikonfigurasi.')}</p>}<p className="text-xs text-muted-foreground">{config.platform}</p>
</div>}</CardContent>
</Card>
<Card>
<CardHeader>
<CardTitle>{l('Resolver identity is not browser identity', 'Identitas resolver bukan identitas peramban')}</CardTitle>
<CardDescription>{l('Configuration is observed locally, without sending an external discovery request.', 'Konfigurasi diamati lokal tanpa permintaan penemuan eksternal.')}</CardDescription>
</CardHeader>
<CardContent className="space-y-3 text-sm text-muted-foreground">
<p>{l('A system resolver may forward to other services. Private or loopback resolver addresses cannot identify a public DNS provider, and matching answers do not establish privacy.', 'Resolver sistem dapat meneruskan ke layanan lain. Alamat resolver privat/loopback tidak mengidentifikasi penyedia DNS publik, dan jawaban cocok tidak membuktikan privasi.')}</p>
<p>{l('Custom resolver traffic can leave this host. Leave the field blank to use the backend configuration; no public resolver is silently added.', 'Trafik resolver khusus dapat meninggalkan host ini. Kosongkan bidang untuk konfigurasi backend; tidak ada resolver publik ditambahkan diam-diam.')}</p>
</CardContent>
</Card>
</div>
    {!live && <Alert>
<TriangleAlert className="size-4" />
<AlertTitle>{l('Live mode is paused', 'Mode langsung dijeda')}</AlertTitle>
<AlertDescription>{l('Repeating checks have stopped and the current browser request was aborted. A backend DNS query already sent may finish within its bounded timeout. Resume and explicitly start another check.', 'Pemeriksaan berulang berhenti dan permintaan peramban dibatalkan. Kueri DNS backend yang telah dikirim dapat selesai dalam batas waktunya. Lanjutkan lalu mulai pemeriksaan lagi secara eksplisit.')}</AlertDescription>
</Alert>}
    <Card>
<CardHeader>
<CardTitle>{l('Resolver workbench', 'Workbench resolver')}</CardTitle>
<CardDescription>{l('Records, cross-resolver comparison, reverse lookup and DNSSEC behavior. Up to three resolvers; each run is time- and query-bounded.', 'Record, perbandingan antarresolver, pencarian balik dan perilaku DNSSEC. Hingga tiga resolver; tiap proses dibatasi waktu dan kueri.')}</CardDescription>
</CardHeader>
<CardContent>
      <Tabs value={mode} onValueChange={value => { if (running || scheduled) return; setMode(value as Mode); form.clearErrors(); }}>
<TabsList className="mb-5 h-auto flex-wrap">
<TabsTrigger value="records" disabled={running || scheduled}>{l('Records', 'Record')}</TabsTrigger>
<TabsTrigger value="compare" disabled={running || scheduled}>{l('Compare resolvers', 'Bandingkan resolver')}</TabsTrigger>
<TabsTrigger value="reverse" disabled={running || scheduled}>{l('Reverse lookup', 'Pencarian balik')}</TabsTrigger>
<TabsTrigger value="dnssec" disabled={running || scheduled}>DNSSEC</TabsTrigger>
</TabsList>
<TabsContent value={mode}>
      <Form {...form}>
<form className="space-y-4" onSubmit={form.handleSubmit(submit)}>
<fieldset disabled={running || scheduled || !live} className="grid gap-4 lg:grid-cols-2">
        {mode !== 'dnssec' && <FormField control={form.control} name="name" rules={{ validate: value => validDnsName(value, mode === 'reverse') || (mode === 'reverse' ? l('Enter a numeric IPv4 or IPv6 address.', 'Masukkan alamat IPv4 atau IPv6 numerik.') : l('Enter a DNS name, not a URL or host:port.', 'Masukkan nama DNS, bukan URL atau host:port.')) }} render={({ field }) => <FormItem>
<FormLabel htmlFor="dns-name">{mode === 'reverse' ? l('IP address', 'Alamat IP') : l('DNS name', 'Nama DNS')}</FormLabel>
<FormControl>
<Input {...field} id="dns-name" placeholder={mode === 'reverse' ? '127.0.0.1' : 'example.com'} maxLength={253} autoComplete="off" spellCheck={false} />
</FormControl>
<FormMessage />
</FormItem>} />}
        <FormField control={form.control} name="servers" rules={{ validate: value => { try { const parsed = parseDnsServers(value); return mode !== 'compare' || parsed.length === 0 || parsed.length >= 2 || l('Compare needs at least two explicit resolvers, or leave blank for system resolvers.', 'Bandingkan membutuhkan dua resolver eksplisit, atau kosongkan untuk resolver sistem.'); } catch (error) { return error instanceof Error ? error.message : 'Invalid resolver'; } } }} render={({ field }) => <FormItem className={mode === 'dnssec' ? 'lg:col-span-2' : ''}>
<FormLabel htmlFor="dns-servers">{l('Custom numeric resolvers (optional)', 'Resolver numerik khusus (opsional)')}</FormLabel>
<FormControl>
<Input {...field} id="dns-servers" placeholder="127.0.0.1:5353, [::1]:5353" maxLength={256} autoComplete="off" spellCheck={false} />
</FormControl>
<FormDescription>{l('Blank = system; max 3. IPv4, IPv6, IPv4:port or [IPv6]:port. No provider is added automatically.', 'Kosong = sistem; maks. 3. IPv4, IPv6, IPv4:port atau [IPv6]:port. Tidak ada penyedia ditambahkan otomatis.')}</FormDescription>
<FormMessage />
</FormItem>} />
        {['records', 'compare'].includes(mode) && <FormField control={form.control} name="types" rules={{ validate: value => value.length > 0 && value.every(type => recordTypes.includes(type)) || l('Select at least one record type.', 'Pilih setidaknya satu jenis record.') }} render={({ field }) => <FormItem className="lg:col-span-2">
<FormLabel>{l('Record types', 'Jenis record')}</FormLabel>
<div className="flex flex-wrap gap-x-5 gap-y-3">{recordTypes.map(type => <Label key={type} className="flex items-center gap-2">
<Checkbox checked={field.value.includes(type)} aria-label={'DNS record ' + type} disabled={running || scheduled || !live} onCheckedChange={checked => field.onChange(checked ? [...field.value, type] : field.value.filter(item => item !== type))} />{type}</Label>)}</div>
<FormDescription>{l('PTR expects a reverse DNS zone name here; use Reverse lookup for a numeric IP.', 'PTR mengharapkan nama zona DNS balik di sini; gunakan Pencarian balik untuk IP numerik.')}</FormDescription>
<FormMessage />
</FormItem>} />}
      </fieldset>
      {mode === 'dnssec' && <Alert>
<ShieldCheck className="size-4" />
<AlertTitle>{l('Resolver behavior test, not zone cryptographic validation', 'Uji perilaku resolver, bukan validasi kriptografi zona')}</AlertTitle>
<AlertDescription>{l('Queries known valid and intentionally broken signed test zones. The backend reports whether each selected resolver behaves like a validator. SERVFAIL alone is inconclusive; this does not verify arbitrary zone signatures or the browser DNS path.', 'Mengueri zona uji bertanda tangan valid dan rusak sengaja. Backend melaporkan apakah resolver terpilih berperilaku sebagai validator. SERVFAIL saja tidak pasti; ini tidak memverifikasi tanda tangan zona sembarang atau jalur DNS peramban.')}</AlertDescription>
</Alert>}
      <div className="flex flex-wrap items-center gap-3">
<Button type="submit" disabled={running || scheduled || !live}>{running ? <LoaderCircle className="size-4 animate-spin" /> : <Play className="size-4" />}{l('Run DNS check', 'Jalankan pemeriksaan DNS')}</Button>
<div className="flex items-center gap-2">
<Switch id="dns-repeat" aria-label="Scheduled repeat" checked={scheduled} disabled={!live || running && !scheduled} onCheckedChange={checked => checked ? void startSchedule() : halt()} />
<Label htmlFor="dns-repeat">{l('Scheduled repeat', 'Pengulangan terjadwal')}</Label>
</div>
<Select value={interval} onValueChange={setIntervalSeconds} disabled={scheduled}>
<SelectTrigger aria-label="DNS repeat interval" className="w-36">
<SelectValue />
</SelectTrigger>
<SelectContent>{['15', '30', '60'].map(value => <SelectItem value={value} key={value}>{value} {l('seconds', 'detik')}</SelectItem>)}</SelectContent>
</Select>{(scheduled || running) && <Button type="button" variant="outline" onClick={halt}>
<Square className="size-4" />{l('Stop repeat', 'Hentikan pengulangan')}</Button>}<Badge variant="outline">{running ? l('Querying backend…', 'Mengueri backend…') : scheduled ? l('Repeat active', 'Pengulangan aktif') : l('Manual only', 'Manual saja')}</Badge>
</div>
<p className="text-xs text-muted-foreground">{l('Repeat is opt-in per visit and uses the current frozen form settings. Ticks never overlap; leaving the page or pausing live stops repeat. Stopping the browser request cannot unsend DNS packets already sent by the backend.', 'Pengulangan dipilih setiap kunjungan dan memakai pengaturan formulir yang dibekukan. Tick tidak tumpang tindih; meninggalkan halaman atau menjeda mode langsung menghentikannya. Menghentikan permintaan peramban tidak menarik paket DNS yang sudah dikirim backend.')}</p>
</form>
</Form>
      </TabsContent>
</Tabs>
    </CardContent>
</Card>
    {requestError && <Alert variant="destructive">
<AlertTitle>{l('DNS request failed', 'Permintaan DNS gagal')}</AlertTitle>
<AlertDescription>{requestError}{result && ' ' + l('The results below are from the previous completed run.', 'Hasil di bawah berasal dari proses selesai sebelumnya.')}</AlertDescription>
</Alert>}
    {!result ? <Card>
<Empty>
<EmptyHeader>
<EmptyMedia variant="icon">
<Globe />
</EmptyMedia>
<EmptyTitle>{l('No DNS query has run', 'Belum ada kueri DNS dijalankan')}</EmptyTitle>
<EmptyDescription>{l('Choose a DNS operation and Run. No fabricated resolver locations, leak verdicts or sample answers are displayed.', 'Pilih operasi DNS lalu Run. Tidak ada lokasi resolver, putusan kebocoran atau jawaban contoh yang dibuat-buat.')}</EmptyDescription>
</EmptyHeader>
</Empty>
</Card> : <div className="space-y-5" data-testid="dns-results">
      <Card>
<CardHeader>
<div className="flex flex-wrap items-center justify-between gap-3">
<div className="space-y-1">
<CardTitle>{l('DNS observation', 'Pengamatan DNS')} · {result.name || 'DNSSEC'}</CardTitle>
<CardDescription>{new Date(result.checkedAt).toLocaleString()} · {result.mode} · {l('Source: backend host', 'Sumber: host backend')}{attemptedAt && Date.parse(attemptedAt) > Date.parse(result.checkedAt) && requestError && ' · ' + l('previous result', 'hasil sebelumnya')}</CardDescription>
</div>
<div className="flex gap-2">
<Button variant="outline" size="sm" onClick={() => download('portscope-dns-' + result.mode + '.json', JSON.stringify(result, null, 2))}>
<ArrowDownToLine className="size-3" />JSON</Button>
<Button variant="outline" size="sm" onClick={() => download('portscope-dns-' + result.mode + '.csv', toCsv([['checkedAt', 'server', 'type', 'status', 'durationMs', 'answers', 'error'], ...result.results.map(row => [result.checkedAt, row.server, row.type, row.status, row.durationMs, JSON.stringify(row.answers), row.error])]), 'text/csv;charset=utf-8')}>CSV</Button>
</div>
</div>
</CardHeader>
<CardContent className="flex flex-wrap gap-2">
<Badge variant="secondary">{servers.length} {l('resolvers observed', 'resolver teramati')}</Badge>
<Badge variant="outline">{result.results.filter(row => row.status === 'answer').length} {l('answers', 'jawaban')}</Badge>
<Badge variant="outline">{result.results.filter(row => row.status === 'error').length} {l('query errors', 'galat kueri')}</Badge>
<Badge variant="outline">{l('Not a browser DNS leak result', 'Bukan hasil kebocoran DNS peramban')}</Badge>
</CardContent>
</Card>
      {comparable.length > 0 && <Card>
<CardHeader>
<CardTitle>{l('Resolver answer comparison', 'Perbandingan jawaban resolver')}</CardTitle>
<CardDescription>{l('Ignores ordering and TTL when comparing returned answers. Matching answers are not proof of validation or privacy; differences may reflect caches, CDN geography or split DNS.', 'Mengabaikan urutan dan TTL saat membandingkan jawaban. Jawaban sama bukan bukti validasi/privasi; perbedaan bisa karena cache, geografi CDN atau DNS terpisah.')}</CardDescription>
</CardHeader>
<CardContent>
<div className="flex flex-wrap gap-2">{comparable.map(item => <Badge key={item.type} variant="outline">{item.type}: {!item.complete ? l('inconclusive', 'tidak pasti') : item.agree ? l('answers agree', 'jawaban sama') : l('answers differ', 'jawaban berbeda')}</Badge>)}</div>
</CardContent>
</Card>}
      {dnssec && <Card>
<CardHeader>
<CardTitle className="flex items-center gap-2">
<ShieldCheck className="size-4" />{l('DNSSEC resolver behavior', 'Perilaku resolver DNSSEC')}</CardTitle>
<CardDescription>{l('Backend behavior checks, not DNSSEC proof for your chosen domain', 'Pemeriksaan perilaku backend, bukan bukti DNSSEC domain pilihan')}</CardDescription>
</CardHeader>
<CardContent>
<Badge variant={dnssec.status === 'validating' ? 'secondary' : 'outline'}>{dnssec.status}</Badge>
<p className="mt-3 text-sm text-muted-foreground">{dnssec.explanation}</p>
<Accordion type="single" collapsible className="mt-3">
<AccordionItem value="dnssec-evidence">
<AccordionTrigger>{l('Show actual test observations', 'Tampilkan pengamatan uji nyata')}</AccordionTrigger>
<AccordionContent>
<pre className="max-h-96 overflow-auto rounded-md bg-muted p-4 text-xs">{JSON.stringify(dnssec.tests, null, 2)}</pre>
</AccordionContent>
</AccordionItem>
</Accordion>
</CardContent>
</Card>}
      <div className="grid gap-4 xl:grid-cols-2">{servers.map(server => { const rows = result.results.filter(row => row.server === server); return <Card key={server}>
<CardHeader>
<div className="flex items-center justify-between gap-3">
<CardTitle className="break-all font-mono text-sm">{server}</CardTitle>
<Button variant="ghost" size="icon" aria-label={l('Copy observed resolver ', 'Salin resolver teramati ') + server} onClick={() => void copy(server)}>
<Copy className="size-4" />
</Button>
</div>
<CardDescription>{rows.length} {l('queries · backend resolver', 'kueri · resolver backend')}</CardDescription>
</CardHeader>
<CardContent>
<Table>
<TableHeader>
<TableRow>
<TableHead>Type</TableHead>
<TableHead>Status</TableHead>
<TableHead>{l('Time', 'Waktu')}</TableHead>
<TableHead>{l('Records', 'Record')}</TableHead>
</TableRow>
</TableHeader>
<TableBody>{rows.map((row, index) => <TableRow key={row.type + index}>
<TableCell className="font-mono">{row.type}</TableCell>
<TableCell>
<Badge variant={row.status === 'answer' ? 'secondary' : 'outline'}>{row.status}</Badge>
</TableCell>
<TableCell className="whitespace-nowrap">{formatMs(row.durationMs)}</TableCell>
<TableCell>{row.answers.length}</TableCell>
</TableRow>)}</TableBody>
</Table>
<Accordion type="multiple" className="mt-3">{rows.map((row, index) => <AccordionItem value={row.type + index} key={row.type + index}>
<AccordionTrigger>
<span className="text-left">{row.type}{row.name ? ' · ' + row.name : ''} · {row.status}</span>
</AccordionTrigger>
<AccordionContent>{row.error && <p className="mb-3 break-words text-sm text-destructive">{row.error}</p>}{row.answers.length ? row.answers.map((value, answerIndex) => <pre key={answerIndex} className="mb-2 max-h-56 overflow-auto whitespace-pre-wrap break-words rounded-md border bg-muted/40 p-3 font-mono text-xs">{answer(value)}</pre>) : <p className="text-sm text-muted-foreground">{row.status === 'nodata' ? l('No records returned for this query. This does not imply the domain is unsafe or absent.', 'Tidak ada record dikembalikan. Ini tidak berarti domain tidak aman atau tidak ada.') : l('No answer is available for this query.', 'Tidak ada jawaban untuk kueri ini.')}</p>}</AccordionContent>
</AccordionItem>)}</Accordion>
</CardContent>
</Card>; })}</div>{!result.results.length && <Alert>
<AlertTitle>{l('No query observations returned', 'Tidak ada pengamatan kueri dikembalikan')}</AlertTitle>
<AlertDescription>{l('No success or privacy conclusion can be drawn from an empty result set.', 'Tidak ada kesimpulan keberhasilan atau privasi dari hasil kosong.')}</AlertDescription>
</Alert>}
    </div>}
    {children}
  </div>;
}
export function dnsToolsSelfCheck() { const assert = (condition: unknown) => { if (!condition) throw new Error('DNS validation self-check failed'); }; for (const value of ['127.0.0.1:5353', '[::1]:5353', '::1', '1.1.1.1']) assert(parseDnsServers(value).length === 1); for (const value of ['https://resolver.test', 'resolver.test', '127.0.0.1:0', '127.0.0.1:65536', '999.0.0.1', '1.1.1.1,1.1.1.1', '1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4']) { let rejected = false; try { parseDnsServers(value); } catch { rejected = true; } assert(rejected); } assert(validDnsName('_dmarc.example.test') && validDnsName('127.0.0.1', true) && !validDnsName('host:443') && !validDnsName('http://host')); assert(dnsComparisonSignature([{ address: '127.0.0.1', ttl: 60 }]) === dnsComparisonSignature([{ ttl: 5, address: '127.0.0.1' }])); assert(dnsComparisonSignature([['one', 'two']]) !== dnsComparisonSignature([['two', 'one']])); return 'DNS resolver, name and comparison validation checks passed'; }
export default DnsTools;
