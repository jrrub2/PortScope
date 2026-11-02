import { useCallback, useEffect, useRef, useState } from 'react';
import { useForm } from 'react-hook-form';
import { Activity, ArrowDownToLine, ChevronLeft, ChevronRight, CircleHelp, Copy, Ellipsis, LoaderCircle, Maximize2, Minimize2, Network, Play, ShieldCheck, Square, TriangleAlert } from 'lucide-react';
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from 'recharts';
import { toast } from 'sonner';
import type { DiagnosticKind, DiagnosticsHop, DiagnosticsJob, DiagnosticsSample, DnsResponse, NetworkSnapshot } from '@/lib/types';
import { cn, copyText, download, formatAge, formatMs, toCsv } from '@/lib/utils';
import { getLocale } from '@/lib/i18n';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { ChartContainer, ChartTooltip, ChartTooltipContent } from '@/components/ui/chart';
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from '@/components/ui/dropdown-menu';
import { Empty, EmptyDescription, EmptyHeader, EmptyMedia, EmptyTitle } from '@/components/ui/empty';
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from '@/components/ui/form';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Progress } from '@/components/ui/progress';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';

const l = (en: string, id: string) => getLocale() === 'id' ? id : en;
const kinds: { value: DiagnosticKind; label: string }[] = [{ value: 'ping', label: 'Ping (ICMP)' }, { value: 'mtr', label: 'Traceroute / MTR (ICMP)' }, { value: 'tcp', label: 'TCP connect' }, { value: 'tls', label: 'TLS handshake' }];
interface DiagnosticForm { target: string; kind: DiagnosticKind; runMode: 'continuous' | 'counted'; family: string; port: string; cycles: string; intervalMs: string; timeoutMs: string; maxHops: string }
const integer = (value: string, min: number, max: number) => /^\d+$/.test(value) && Number(value) >= min && Number(value) <= max;
export function validDiagnosticTarget(value: string) {
  if (!value || value.length > 253 || value !== value.trim() || /[\s/\\@?#%]/.test(value)) return false;
  if (/^\d+(?:\.\d+){3}$/.test(value)) return value.split('.').every(octet => /^(?:0|[1-9]\d{0,2})$/.test(octet) && Number(octet) <= 255);
  if (value.includes(':')) { try { return new URL('http://[' + value + ']/').hostname.startsWith('['); } catch { return false; } }
  return value.replace(/\.$/, '').split('.').every(label => label.length > 0 && label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label)) && !/^[\d.]+$/.test(value);
}
function active(job: DiagnosticsJob | null) { return job?.status === 'resolving' || job?.status === 'running'; }
function apiMessage(body: unknown, fallback: string) { const error = body && typeof body === 'object' && 'error' in body ? body.error : null; return typeof error === 'string' ? error : error && typeof error === 'object' && 'message' in error && typeof error.message === 'string' ? error.message : fallback; }
export function validDiagnosticSamples(value: unknown, limit: number): value is DiagnosticsSample[] {
  return Array.isArray(value) && value.length <= limit && value.every(sample => sample && typeof sample === 'object' && typeof sample.at === 'string' && /^\d{4}-\d{2}-\d{2}T/.test(sample.at) && Number.isFinite(Date.parse(sample.at)) && (sample.ms === null || typeof sample.ms === 'number' && Number.isFinite(sample.ms) && sample.ms >= 0) && typeof sample.status === 'string' && sample.status.length > 0 && sample.status.length <= 100);
}
export function hopHistory(hop: DiagnosticsHop | undefined) { return hop?.address ? hop.samples : undefined; }
export function diagnosticHopAddresses(hops: DiagnosticsHop[]) {
  return [...new Set(hops.map(hop => hop.address).filter((address): address is string => !!address && validDiagnosticTarget(address) && (address.includes(':') || /^\d+(?:\.\d+){3}$/.test(address))))];
}
export function diagnosticPtrName(value: unknown, address: string): string | null {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  const result = value as Partial<DnsResponse>;
  if (result.ok !== true || result.source !== 'backend' || result.mode !== 'reverse' || result.name !== address.toLowerCase() || !Array.isArray(result.results) || result.results.length > 3) return null;
  for (const row of result.results) {
    if (!row || row.type !== 'PTR' || row.status !== 'answer' || !Array.isArray(row.answers)) continue;
    for (const answer of row.answers.slice(0, 32)) {
      const name = typeof answer === 'string' ? answer.replace(/\.$/, '') : '';
      if (name.length > 0 && name.length <= 253 && !/[\s\x00-\x1f\x7f]/.test(name) && name.split('.').every(label => /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/i.test(label))) return name;
    }
  }
  return null;
}
function readJob(value: unknown): DiagnosticsJob {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid diagnostic job response.');
  const job = value as Partial<DiagnosticsJob>;
  const numberOrNull = (value: unknown) => value === null || typeof value === 'number' && Number.isFinite(value) && value >= 0;
  if (typeof job.id !== 'string' || !/^[a-zA-Z0-9_-]{1,100}$/.test(job.id) || !kinds.some(kind => kind.value === job.kind) || typeof job.target !== 'string' || !['resolving', 'running', 'completed', 'cancelled', 'error'].includes(String(job.status)) || !Array.isArray(job.hops) || !Array.isArray(job.samples) || job.hops.length > 32 || job.samples.length > 240 || !Number.isSafeInteger(job.cycle) || job.cycle! < 0 || typeof job.updatedAt !== 'string' || !Number.isFinite(Date.parse(job.updatedAt)) || (job.continuous !== undefined && typeof job.continuous !== 'boolean') || (job.continuous === true ? job.cycles !== null || !['ping', 'mtr'].includes(job.kind!) : !Number.isInteger(job.cycles) || job.cycles! < 1 || job.cycles! > 300)) throw new Error('Malformed diagnostic job response.');
  if ((job.family !== 4 && job.family !== 6) || typeof job.reached !== 'boolean' || typeof job.startedAt !== 'string' || !Number.isFinite(Date.parse(job.startedAt)) || job.hops.some(hop => !hop || !Number.isInteger(hop.ttl) || hop.ttl < 1 || hop.ttl > 32 || typeof hop.status !== 'string' || ![hop.sent, hop.received, hop.lost, hop.lossPercent].every(value => typeof value === 'number' && Number.isFinite(value) && value >= 0) || (hop.address !== null && typeof hop.address !== 'string') || ![hop.lastMs, hop.minMs, hop.avgMs, hop.maxMs, hop.jitterMs].every(numberOrNull) || hop.samples !== undefined && !validDiagnosticSamples(hop.samples, 60)) || new Set(job.hops.map(hop => hop.ttl)).size !== job.hops.length || !validDiagnosticSamples(job.samples, 240)) throw new Error('Malformed diagnostic observations.');
  return job as DiagnosticsJob;
}
async function cancelJob(id: string, keepalive = false) { const response = await fetch('/api/diagnostics/' + encodeURIComponent(id), { method: 'DELETE', keepalive }); if (!response.ok && response.status !== 404) { const body: unknown = await response.json().catch(() => null); throw new Error(apiMessage(body, 'Unable to cancel diagnostic (HTTP ' + response.status + ').')); } return response; }
function HistoryChart({ samples, compact = false, dense = false, fit = false, label, kind = 'mtr', testId }: { samples: DiagnosticsSample[]; compact?: boolean; dense?: boolean; fit?: boolean; label: string; kind?: DiagnosticKind; testId?: string }) {
  const data = samples.map(sample => ({ ...sample, time: Date.parse(sample.at) }));
  const replies = samples.filter(sample => sample.ms !== null);
  return <div className={compact ? 'w-40' : fit ? 'flex min-h-0 flex-1 flex-col' : 'min-w-0'} data-testid={testId} data-sample-count={samples.length} data-timeout-count={samples.filter(sample => sample.ms === null).length} data-first-at={samples[0]?.at} data-last-at={samples.at(-1)?.at}>
    <ChartContainer role="img" aria-label={label} config={{ ms: { label: kind === 'tcp' ? l('TCP connect (ms)', 'Koneksi TCP (ms)') : kind === 'tls' ? l('TLS handshake (ms)', 'Handshake TLS (ms)') : l('Observed RTT (ms)', 'RTT teramati (ms)'), color: 'var(--chart-1)' } }} className={compact ? cn('w-40 aspect-auto', dense ? 'h-6' : 'h-12') : fit ? 'min-h-24 w-full flex-1 aspect-auto' : 'h-64 w-full aspect-auto'} initialDimension={compact ? { width: 160, height: 48 } : undefined}>
      <LineChart accessibilityLayer data={data} margin={compact ? { top: 4, right: 4, bottom: 4, left: 4 } : { top: 8, right: 8 }}>
        {!compact && <CartesianGrid vertical={false} />}
        <XAxis hide={compact} dataKey="time" type="number" domain={['dataMin', 'dataMax']} tickLine={false} axisLine={false} minTickGap={40} tickFormatter={value => new Date(Number(value)).toLocaleTimeString()} />
        <YAxis hide={compact} tickLine={false} axisLine={false} width={48} />
        <ChartTooltip filterNull={false} content={<ChartTooltipContent labelFormatter={(value, payload) => { const sample = payload?.[0]?.payload; return new Date(sample?.at ?? Number(value)).toLocaleString() + (sample?.status ? ' · ' + sample.status : ''); }} formatter={(value, _name, item) => <div className="flex min-w-28 items-center justify-between gap-3"><span className="text-muted-foreground">{item.payload.status}</span><span className="font-mono">{value === null || value === undefined ? l('No reply', 'Tanpa balasan') : Number(value).toFixed(2) + ' ms'}</span></div>} />} />
        <Line dataKey="ms" stroke="var(--color-ms)" strokeWidth={compact ? 1.5 : 2} dot={{ r: compact ? 1.5 : 2 }} connectNulls={false} isAnimationActive={false} />
      </LineChart>
    </ChartContainer>
    {compact ? <span className="sr-only">{samples.length} {l('observations', 'pengamatan')}; {samples.length - replies.length} {l('without reply', 'tanpa balasan')}</span> : <p className="mt-2 text-xs text-muted-foreground">{samples.length}/{kind === 'mtr' ? 60 : 240} {l('retained observations', 'pengamatan tersimpan')} · {samples.length - replies.length} {l('without reply; nulls are gaps, not zero milliseconds', 'tanpa balasan; null adalah celah, bukan nol milidetik')}{samples.length > 0 && ' · ' + new Date(samples[0].at).toLocaleTimeString() + ' → ' + new Date(samples[samples.length - 1].at).toLocaleTimeString()}</p>}
  </div>;
}
function Status({ job, starting, stopping }: { job: DiagnosticsJob | null; starting: boolean; stopping: boolean }) { return <Badge data-testid="diagnostic-status" variant={job?.status === 'error' ? 'destructive' : active(job) ? 'secondary' : 'outline'}>{starting || stopping || active(job) ? <LoaderCircle className="size-3 animate-spin" /> : job?.status === 'completed' ? <ShieldCheck className="size-3" /> : <CircleHelp className="size-3" />}{starting ? l('Starting…', 'Memulai…') : stopping ? l('Stopping…', 'Menghentikan…') : job?.status ?? l('Not started', 'Belum dimulai')}</Badge>; }
const ms = (value: number | null | undefined) => value == null ? '—' : value.toFixed(2);

export function hopPageWindow(height: number, total: number, requestedPage: number, rowHeight = 40, headerHeight = 40) {
  const count = Number.isFinite(total) ? Math.max(0, Math.min(32, Math.floor(total))) : 0;
  const row = Number.isFinite(rowHeight) ? Math.max(40, rowHeight) : 40;
  const available = Number.isFinite(height) ? Math.max(0, height) : 0;
  const header = Number.isFinite(headerHeight) ? Math.max(0, headerHeight) : 40;
  const size = Math.max(1, Math.min(32, Math.floor((available - header - 2) / row)));
  const pages = Math.max(1, Math.ceil(count / size));
  const page = Math.max(0, Math.min(pages - 1, Number.isFinite(requestedPage) ? Math.floor(requestedPage) : 0));
  return { size, pages, page, start: page * size, end: Math.min(count, (page + 1) * size) };
}

export function Diagnostics({ network, live, initialTarget = '', initialKind = 'ping', onFocusChange }: { network: NetworkSnapshot | null; live: boolean; initialTarget?: string; initialKind?: DiagnosticKind; onFocusChange?: (focus: boolean) => void }) {
  const [job, setJob] = useState<DiagnosticsJob | null>(null);
  const [starting, setStarting] = useState(false), [stopping, setStopping] = useState(false);
  const [error, setError] = useState(''), [streamStatus, setStreamStatus] = useState('idle');
  const [selectedTtl, setSelectedTtl] = useState(1), [resultTab, setResultTab] = useState('hops');
  const [focus, setFocus] = useState(false), [hopPage, setHopPage] = useState(0), [hopPageSize, setHopPageSize] = useState(8);
  const [resolveNames, setResolveNames] = useState(false), [hopNames, setHopNames] = useState<Record<string, string | null>>({});
  const namesEnabled = useRef(false), nameCache = useRef(new Map<string, string | null>()), nameRequest = useRef<AbortController | null>(null);
  const hopViewport = useRef<HTMLDivElement>(null), resultsRef = useRef<HTMLDivElement>(null), setupRef = useRef<HTMLDivElement>(null);
  const icmpUnavailable = !!network?.platform && network.platform !== 'win32';
  const mounted = useRef(false), liveRef = useRef(live); liveRef.current = live;
  const currentJob = useRef<DiagnosticsJob | null>(null), source = useRef<EventSource | null>(null);
  const creating = useRef(false), cancelling = useRef(false), generation = useRef(0);
  const form = useForm<DiagnosticForm>({ shouldUnregister: true, defaultValues: { target: initialTarget, kind: initialKind, runMode: initialKind === 'mtr' ? 'continuous' : 'counted', family: initialTarget.includes(':') ? '6' : '4', port: '443', cycles: initialKind === 'tls' ? '1' : '20', intervalMs: '1000', timeoutMs: '1000', maxHops: '24' } });
  const selectedKind = form.watch('kind');
  const continuous = ['ping', 'mtr'].includes(selectedKind) && form.watch('runMode') === 'continuous';
  const unsupportedSelection = icmpUnavailable && ['ping', 'mtr'].includes(selectedKind);
  useEffect(() => { onFocusChange?.(focus); return () => onFocusChange?.(false); }, [focus, onFocusChange]);
  const toggleFocus = () => { setFocus(value => !value); requestAnimationFrame(() => { window.scrollTo({ top: 0 }); (focus ? setupRef : resultsRef).current?.focus(); }); };
  useEffect(() => {
    const viewport = hopViewport.current;
    if (!focus || resultTab !== 'hops' || !viewport) return;
    const table = viewport.querySelector('table');
    const measure = () => {
      const rowHeight = Math.max(40, ...Array.from(table?.tBodies[0]?.rows ?? []).map(row => row.getBoundingClientRect().height));
      setHopPageSize(hopPageWindow(viewport.clientHeight, 32, 0, rowHeight, table?.tHead?.getBoundingClientRect().height ?? 40).size);
    };
    const observer = new ResizeObserver(measure); observer.observe(viewport); if (table) observer.observe(table); measure();
    return () => observer.disconnect();
  }, [focus, resultTab, job?.id]);
  const closeStream = useCallback(() => { source.current?.close(); source.current = null; }, []);
  const abortNames = useCallback(() => { nameRequest.current?.abort(); nameRequest.current = null; }, []);
  const changeResolveNames = useCallback((enabled: boolean) => { namesEnabled.current = enabled; setResolveNames(enabled); if (!enabled) abortNames(); }, [abortNames]);
  const showJob = useCallback((next: DiagnosticsJob) => {
    if (currentJob.current?.id !== next.id) { abortNames(); nameCache.current.clear(); if (mounted.current) setHopNames({}); }
    currentJob.current = next; if (mounted.current) setJob(next);
  }, [abortNames]);
  const resolveNext = useCallback(async function resolveNext() {
    const current = currentJob.current;
    if (!mounted.current || !namesEnabled.current || !liveRef.current || creating.current || nameRequest.current || current?.kind !== 'mtr' || nameCache.current.size >= 128) return;
    const address = diagnosticHopAddresses(current.hops).find(address => !nameCache.current.has(address));
    if (!address) return;
    // ponytail: one PTR attempt per IP, at most 128 per job; start a new job to refresh names or extend this to TTL-aware caching.
    nameCache.current.set(address, null);
    const controller = new AbortController(); nameRequest.current = controller;
    const timeout = window.setTimeout(() => controller.abort(), 12000);
    let name: string | null = null;
    try {
      const response = await fetch('/api/dns', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ mode: 'reverse', name: address }), signal: controller.signal, cache: 'no-store' });
      if (response.ok) name = diagnosticPtrName(await response.json(), address);
    } catch { /* Missing PTR, failed DNS and cancellation leave the measured IP unchanged. */ }
    finally {
      window.clearTimeout(timeout);
      if (nameRequest.current === controller) {
        nameRequest.current = null;
        if (!controller.signal.aborted && mounted.current && namesEnabled.current && liveRef.current && currentJob.current?.id === current.id) { nameCache.current.set(address, name); setHopNames(previous => ({ ...previous, [address]: name })); }
        void resolveNext();
      }
    }
  }, []);
  const hopAddresses = diagnosticHopAddresses(job?.hops ?? []).join(',');
  useEffect(() => { void resolveNext(); }, [resolveNames, live, starting, job?.id, hopAddresses, resolveNext]);
  const stop = useCallback(async () => {
    generation.current++; closeStream(); abortNames(); namesEnabled.current = false;
    if (mounted.current) { setResolveNames(false); setStreamStatus('stopped'); }
    const current = currentJob.current;
    if (!current || !active(current) || cancelling.current) return;
    cancelling.current = true;
    if (mounted.current) setStopping(true);
    try { const response = await cancelJob(current.id); if (response.status === 404) showJob({ ...current, status: 'error', error: l('Job is no longer available on this server.', 'Job tidak lagi tersedia di server ini.') }); else { const body: unknown = await response.json(); if (!body || typeof body !== 'object' || !('job' in body)) throw new Error('Cancellation response did not confirm job state.'); showJob(readJob(body.job)); } }
    catch (error) { if (mounted.current) { setError(error instanceof Error ? error.message : 'Cancellation failed.'); toast.error(l('Cancellation could not be confirmed. Retry Stop. Closing this workspace also releases its server lease.', 'Pembatalan belum terkonfirmasi. Coba Stop lagi. Menutup workspace juga melepas lease servernya.')); } }
    finally { cancelling.current = false; if (mounted.current) setStopping(false); }
  }, [closeStream, showJob, abortNames]);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; generation.current++; closeStream(); abortNames(); const current = currentJob.current; if (current && active(current)) void cancelJob(current.id, true).catch(() => {}); }; }, [closeStream, abortNames]);
  useEffect(() => { if (!live) void stop(); }, [live, stop]);
  useEffect(() => { const cancel = () => { abortNames(); namesEnabled.current = false; setResolveNames(false); const current = currentJob.current; if (current && active(current)) void cancelJob(current.id, true).catch(() => {}); }; window.addEventListener('pagehide', cancel); return () => window.removeEventListener('pagehide', cancel); }, [abortNames]);

  function subscribe(id: string) {
    closeStream(); const events = new EventSource('/api/diagnostics/' + encodeURIComponent(id) + '/stream'); source.current = events; setStreamStatus('connecting');
    events.onopen = () => { if (mounted.current && source.current === events) setStreamStatus('connected'); };
    events.addEventListener('job', event => {
      if (!mounted.current || source.current !== events) return;
      try { const next = readJob(JSON.parse((event as MessageEvent).data)); if (next.id !== id) throw new Error('Mismatched diagnostic stream.'); showJob(next); if (!active(next)) { events.close(); source.current = null; setStreamStatus('finished'); } }
      catch { setError(l('Invalid diagnostic stream update; stop and retry the job.', 'Pembaruan aliran diagnostik tidak valid; hentikan dan coba lagi.')); }
    });
    events.onerror = () => { if (mounted.current && source.current === events) setStreamStatus('reconnecting'); };
  }
  async function start(values: DiagnosticForm) {
    if (!liveRef.current || creating.current || active(currentJob.current) || cancelling.current || icmpUnavailable && ['ping', 'mtr'].includes(values.kind)) return;
    creating.current = true; abortNames(); const run = ++generation.current; setStarting(true); setError(''); setStreamStatus('idle');
    try {
      const spec = { kind: values.kind, target: values.target.trim(), family: Number(values.family), timeoutMs: Number(values.timeoutMs), intervalMs: Number(values.intervalMs), ...(['ping', 'mtr'].includes(values.kind) && values.runMode === 'continuous' ? { continuous: true } : { cycles: Number(values.cycles) }), ...(values.kind === 'mtr' ? { maxHops: Number(values.maxHops) } : {}), ...(['tcp', 'tls'].includes(values.kind) ? { port: Number(values.port) } : {}) };
      // Keep the creation response long enough to learn its ID and cancel if navigation/pause wins the race.
      const response = await fetch('/api/diagnostics', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(spec), cache: 'no-store' });
      const body: unknown = await response.json(); if (!response.ok || !body || typeof body !== 'object' || !('ok' in body) || body.ok !== true || !('job' in body)) throw new Error(apiMessage(body, 'Diagnostic API returned HTTP ' + response.status + '.'));
      const next = readJob(body.job);
      if (!mounted.current || !liveRef.current || generation.current !== run) { await cancelJob(next.id, true); return; }
      setSelectedTtl(1); setHopPage(0); setResultTab(next.kind === 'mtr' ? 'hops' : 'chart'); showJob(next); if (next.kind === 'mtr') { setFocus(true); requestAnimationFrame(() => { window.scrollTo({ top: 0 }); resultsRef.current?.focus(); }); } if (active(next)) subscribe(next.id);
    } catch (error) { if (mounted.current) { setError(error instanceof Error ? error.message : 'Unable to start diagnostic.'); toast.error(l('Diagnostic request failed', 'Permintaan diagnostik gagal')); } }
    finally { creating.current = false; if (mounted.current) setStarting(false); }
  }
  const busy = starting || stopping || active(job);
  const pageCount = Math.max(1, Math.ceil((job?.hops.length ?? 0) / hopPageSize));
  const currentPage = Math.min(hopPage, pageCount - 1);
  const pageStart = currentPage * hopPageSize, pageEnd = Math.min(job?.hops.length ?? 0, pageStart + hopPageSize);
  const visibleHops = focus ? job?.hops.slice(pageStart, pageEnd) ?? [] : job?.hops ?? [];
  const selectedHop = job?.hops.find(hop => hop.ttl === selectedTtl);
  const selectedSamples = hopHistory(selectedHop);
  const lastHop = job?.hops.find(hop => hop.address !== null && hop.address === job.address) ?? (job?.kind === 'mtr' ? undefined : job?.hops.at(-1));
  const peers = Array.from(new Set(network?.connections.flatMap(connection => connection.remoteAddress && !['0.0.0.0', '::', '*'].includes(connection.remoteAddress) ? [connection.remoteAddress] : []) ?? [])).slice(0, 100);
  const exportCsv = () => { if (!job) return; download('portscope-' + job.kind + '-' + job.id + '.csv', toCsv(job.kind === 'mtr' ? [['ttl', 'address', 'status', 'sent', 'received', 'lost', 'lossPercent', 'lastMs', 'minMs', 'avgMs', 'maxMs', 'jitterMs'], ...job.hops.map(hop => [hop.ttl, hop.address, hop.status, hop.sent, hop.received, hop.lost, hop.lossPercent, hop.lastMs, hop.minMs, hop.avgMs, hop.maxMs, hop.jitterMs])] : [['at', 'milliseconds', 'status', 'kind', 'target', 'address'], ...job.samples.map(sample => [sample.at, sample.ms, sample.status, job.kind, job.target, job.address])]), 'text/csv;charset=utf-8'); };
  const exportHopCsv = () => { if (!job) return; download('portscope-mtr-hop-history-' + job.id + '.csv', toCsv([['ttl', 'currentResponder', 'at', 'milliseconds', 'status'], ...job.hops.flatMap(hop => (hopHistory(hop) ?? []).map(sample => [hop.ttl, hop.address, sample.at, sample.ms, sample.status]))]), 'text/csv;charset=utf-8'); };
  const copy = async (value: string) => { try { await copyText(value); toast.success(l('Copied', 'Disalin')); } catch { toast.error(l('Clipboard access failed', 'Akses papan klip gagal')); } };
  const hopName = (address: string | null) => resolveNames && job?.kind === 'mtr' && address ? hopNames[address] : null;
  const hopLabel = (address: string | null) => address ? hopName(address) ? hopName(address) + ' (' + address + ')' : address : l('No responder', 'Tanpa responder');
  const namesHelp = l('Query configured host DNS resolvers for PTR names. Names are unverified labels; missing names keep the IP. DNS does not delay ICMP probes.', 'Kueri resolver DNS host untuk nama PTR. Nama adalah label belum terverifikasi; jika tidak tersedia, IP tetap tampil. DNS tidak menunda probe ICMP.');
  const namesControl = (id: string) => <div className="flex min-h-8 items-center gap-2" title={namesHelp}><Checkbox id={id} checked={resolveNames} onCheckedChange={value => changeResolveNames(value === true)} disabled={!live || starting} aria-describedby={id + '-help'} /><Label htmlFor={id} className="cursor-pointer text-xs">Resolve names</Label><span id={id + '-help'} className="sr-only">{namesHelp}</span></div>;
  return <div data-testid="diagnostic-monitor-view" data-focus={focus} className={cn("min-w-0 space-y-5", focus && "flex min-h-0 flex-1 flex-col gap-3 overflow-hidden space-y-0")}><div ref={setupRef} tabIndex={-1} hidden={focus} className="space-y-5 outline-none">
    <Alert>
<Network className="size-4" />
<AlertTitle>{l('Active network diagnostics — opt in', 'Diagnostik jaringan aktif — pilihan Anda')}</AlertTitle>
<AlertDescription>{l('Run sends traffic from this host to your chosen destination. Nothing is probed automatically on this page. Ping and Traceroute / MTR use native ICMP, TCP tests a connection, and TLS performs a verified handshake. Only test hosts you are authorized to contact.', 'Run mengirim trafik dari host ini ke tujuan pilihan Anda. Tidak ada probe otomatis saat halaman dibuka. Ping dan Traceroute / MTR memakai ICMP native, TCP menguji koneksi, TLS melakukan handshake terverifikasi. Hanya uji host yang diizinkan.')}</AlertDescription>
</Alert>
    {icmpUnavailable && <Alert><TriangleAlert className="size-4" /><AlertTitle>{l('ICMP is unavailable on this backend platform', 'ICMP tidak tersedia pada platform backend ini')}</AlertTitle><AlertDescription>{l('This release runs native Ping and Traceroute / MTR on Windows only. The backend reports ', 'Rilis ini menjalankan Ping dan Traceroute / MTR native hanya pada Windows. Backend melaporkan ') + network?.platform + l('. Choose TCP connect or TLS handshake instead; no ICMP results are simulated.', '. Pilih koneksi TCP atau handshake TLS; hasil ICMP tidak disimulasikan.')}</AlertDescription></Alert>}
    {!live && <Alert>
<TriangleAlert className="size-4" />
<AlertTitle>{l('Live mode is paused', 'Mode langsung dijeda')}</AlertTitle>
<AlertDescription>{l('Cancellation is requested for any active diagnostic. Read its status below for confirmation. Resume live mode before running another test.', 'Pembatalan diminta untuk diagnostik aktif. Lihat status di bawah untuk konfirmasi. Lanjutkan mode langsung sebelum menguji lagi.')}</AlertDescription>
</Alert>}
    {error && <Alert variant="destructive">
<AlertTitle>{l('Diagnostic notice', 'Pemberitahuan diagnostik')}</AlertTitle>
<AlertDescription>{error}</AlertDescription>
</Alert>}
    <Card>
<CardHeader>
<div className="flex flex-wrap items-center justify-between gap-3">
<div className="space-y-1">
<CardTitle>{l('Start a diagnostic', 'Mulai diagnostik')}</CardTitle>
<CardDescription>{l('MTR combines destination-directed traceroute with repeated ICMP probes per TTL. Continuous mode runs while this workspace owns the job, until Stop, pause or close. Counted tests retain the five-minute/300-cycle limit; all modes allow up to 32 hops and two active host jobs.', 'MTR menggabungkan traceroute menuju tujuan dengan probe ICMP berulang per TTL. Mode terus-menerus berjalan selama workspace memiliki job, hingga Stop, jeda atau tutup. Uji terhitung tetap dibatasi lima menit/300 siklus; semua mode hingga 32 hop dan dua job host aktif.')}</CardDescription>
</div>
{!job && <Status job={job} starting={starting} stopping={stopping} />}
</div>
</CardHeader>
<CardContent>
      <Form {...form}>
<form className="space-y-4" onSubmit={form.handleSubmit(start)}>
<fieldset disabled={busy || !live} className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <FormField control={form.control} name="kind" render={({ field }) => <FormItem>
<FormLabel>{l('Diagnostic type', 'Jenis diagnostik')}</FormLabel>
<Select value={field.value} onValueChange={value => { field.onChange(value); form.setValue('runMode', value === 'mtr' ? 'continuous' : 'counted'); }} disabled={busy || !live}>
<FormControl>
<SelectTrigger aria-label="Diagnostic type">
<SelectValue />
</SelectTrigger>
</FormControl>
<SelectContent>{kinds.map(kind => <SelectItem value={kind.value} key={kind.value} disabled={icmpUnavailable && ['ping', 'mtr'].includes(kind.value)}>{kind.label}</SelectItem>)}</SelectContent>
</Select>
</FormItem>} />
        <FormField control={form.control} name="target" rules={{ validate: value => validDiagnosticTarget(value) || l('Enter a hostname or numeric IP, not a URL or host:port.', 'Masukkan hostname atau IP numerik, bukan URL atau host:port.') }} render={({ field }) => <FormItem className="sm:col-span-2">
<FormLabel htmlFor="diagnostic-target">{l('Target hostname or IP', 'Hostname atau IP tujuan')}</FormLabel>
<FormControl>
<Input {...field} id="diagnostic-target" list="diagnostic-peers" placeholder="127.0.0.1" maxLength={253} autoComplete="off" spellCheck={false} />
</FormControl>
<datalist id="diagnostic-peers">{peers.map(peer => <option key={peer} value={peer} />)}</datalist>
<FormMessage />
</FormItem>} />
        <FormField control={form.control} name="family" render={({ field }) => <FormItem>
<FormLabel>{l('Address family', 'Keluarga alamat')}</FormLabel>
<Select value={field.value} onValueChange={field.onChange} disabled={busy || !live}>
<FormControl>
<SelectTrigger aria-label="Address family">
<SelectValue />
</SelectTrigger>
</FormControl>
<SelectContent>
<SelectItem value="4">IPv4</SelectItem>
<SelectItem value="6">IPv6</SelectItem>
</SelectContent>
</Select>
</FormItem>} />
        {['tcp', 'tls'].includes(selectedKind) && <FormField control={form.control} name="port" rules={{ validate: value => integer(value, 1, 65535) || l('Port must be 1–65535.', 'Port harus 1–65535.') }} render={({ field }) => <FormItem>
<FormLabel htmlFor="diagnostic-port">{l('Target port', 'Port tujuan')}</FormLabel>
<FormControl>
<Input {...field} id="diagnostic-port" inputMode="numeric" />
</FormControl>
<FormMessage />
</FormItem>} />}
        {['ping', 'mtr'].includes(selectedKind) && <FormField control={form.control} name="runMode" render={({ field }) => <FormItem><FormLabel>{l('Run mode', 'Mode pengujian')}</FormLabel><Select value={field.value} onValueChange={field.onChange} disabled={busy || !live}><FormControl><SelectTrigger id="diagnostic-run-mode" aria-label={l('Run mode', 'Mode pengujian')}><SelectValue /></SelectTrigger></FormControl><SelectContent><SelectItem value="continuous">{l('Continuous until Stop', 'Terus-menerus hingga Stop')}</SelectItem><SelectItem value="counted">{l('Counted cycles', 'Siklus terhitung')}</SelectItem></SelectContent></Select></FormItem>} />}
        {!continuous && <FormField control={form.control} name="cycles" rules={{ validate: value => integer(value, 1, 300) || l('Use 1–300 cycles.', 'Gunakan 1–300 siklus.') }} render={({ field }) => <FormItem>
<FormLabel htmlFor="diagnostic-cycles">{l('Cycles', 'Siklus')}</FormLabel>
<FormControl>
<Input {...field} id="diagnostic-cycles" inputMode="numeric" />
</FormControl>
<FormMessage />
</FormItem>} />}
        <FormField control={form.control} name="intervalMs" rules={{ validate: value => integer(value, 500, 10000) || l('Use 500–10000 ms.', 'Gunakan 500–10000 ms.') }} render={({ field }) => <FormItem>
<FormLabel htmlFor="diagnostic-interval">{l('Interval (ms)', 'Interval (ms)')}</FormLabel>
<FormControl>
<Input {...field} id="diagnostic-interval" inputMode="numeric" />
</FormControl>
<FormMessage />
</FormItem>} />
        <FormField control={form.control} name="timeoutMs" rules={{ validate: value => integer(value, 250, 3000) || l('Use 250–3000 ms.', 'Gunakan 250–3000 ms.') }} render={({ field }) => <FormItem>
<FormLabel htmlFor="diagnostic-timeout">{l('Timeout (ms)', 'Batas waktu (ms)')}</FormLabel>
<FormControl>
<Input {...field} id="diagnostic-timeout" inputMode="numeric" />
</FormControl>
<FormMessage />
</FormItem>} />
        {selectedKind === 'mtr' && <FormField control={form.control} name="maxHops" rules={{ validate: value => integer(value, 1, 32) || l('Use 1–32 hops.', 'Gunakan 1–32 hop.') }} render={({ field }) => <FormItem>
<FormLabel htmlFor="diagnostic-hops">{l('Maximum hops', 'Hop maksimum')}</FormLabel>
<FormControl>
<Input {...field} id="diagnostic-hops" inputMode="numeric" />
</FormControl>
<FormMessage />
</FormItem>} />}
      </fieldset>
{selectedKind === 'mtr' && <div>{namesControl('diagnostic-resolve-names')}<p className="text-xs text-muted-foreground">{namesHelp}</p></div>}
<p className="text-xs text-muted-foreground">{continuous ? l('Run starts continuous foreground monitoring. It sends traffic until you Stop, pause live mode, or leave this workspace. Background tabs may still monitor; only 60 observations per current hop are retained.', 'Run memulai pemantauan terus-menerus di workspace. Trafik dikirim hingga Stop, jeda mode langsung atau meninggalkan workspace. Tab latar belakang masih dapat memantau; hanya 60 pengamatan per hop saat ini disimpan.') : l('Clicking Run authorizes this counted test. A result can disclose destination addresses. Export only what you intend to share.', 'Menekan Run mengizinkan pengujian terhitung ini. Hasil dapat mengungkap alamat tujuan. Ekspor hanya yang ingin Anda bagikan.')}</p>
<div className="flex flex-wrap gap-2">
<Button type="submit" disabled={busy || !live || unsupportedSelection}>{starting ? <LoaderCircle className="size-4 animate-spin" /> : <Play className="size-4" />}{l('Run diagnostic', 'Jalankan diagnostik')}</Button>
{!job && <Button type="button" variant="outline" disabled={!starting || stopping} onClick={() => void stop()}>
<Square className="size-4" />{l('Stop diagnostic', 'Hentikan diagnostik')}</Button>}{job && <>
<Button type="button" variant="outline" onClick={() => download('portscope-' + job.kind + '-' + job.id + '.json', JSON.stringify(job, null, 2))}>
<ArrowDownToLine className="size-4" />JSON</Button>
<Button type="button" variant="outline" onClick={exportCsv}>CSV</Button>
{job.kind === 'mtr' && <Button type="button" variant="outline" disabled={!job.hops.some(hop => hopHistory(hop)?.length)} onClick={exportHopCsv}>{l('Hop history CSV', 'CSV riwayat hop')}</Button>}
</>}</div>
</form>
</Form>
    </CardContent>
</Card>
    </div>
    {!job ? <Card>
<Empty>
<EmptyHeader>
<EmptyMedia variant="icon">
<Activity />
</EmptyMedia>
<EmptyTitle>{l('No diagnostic has run', 'Belum ada diagnostik dijalankan')}</EmptyTitle>
<EmptyDescription>{l('Choose a target and Run to collect real measurements. An empty view is not a successful test.', 'Pilih tujuan lalu Run untuk mengumpulkan pengukuran nyata. Tampilan kosong bukan pengujian berhasil.')}</EmptyDescription>
</EmptyHeader>
</Empty>
</Card> : <>
      <div ref={resultsRef} tabIndex={-1} className={cn('sticky top-16 z-20 flex flex-wrap items-center justify-between gap-3 rounded-xl border bg-background px-4 py-3 outline-none', focus && 'static shrink-0')}>
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex flex-wrap items-center gap-2"><span className="text-sm font-semibold">{kinds.find(kind => kind.value === job.kind)?.label}</span><Status job={job} starting={starting} stopping={stopping} /></div>
          <p className="truncate font-mono text-xs" title={job.target}>{job.target} · {job.address || l('Resolving…', 'Menyelesaikan…')}{job.port ? ':' + job.port : ''} · IPv{job.family}</p>
          <p className="text-xs text-muted-foreground"><span data-testid={job.continuous ? 'diagnostic-monitoring' : undefined}>{job.continuous ? active(job) ? l('Continuous · until Stop', 'Terus-menerus · hingga Stop') : l('Continuous monitoring stopped.', 'Pemantauan terus-menerus berhenti.') : job.cycle + '/' + job.cycles + ' ' + l('cycles', 'siklus')}</span> · {streamStatus} · {l('Updated ', 'Diperbarui ')}{new Date(job.updatedAt).toLocaleTimeString()}</p>
        </div>
        <div className="flex shrink-0 flex-wrap items-center gap-2">
          {job.kind === 'mtr' && namesControl('diagnostic-resolve-names-results')}
          <DropdownMenu><DropdownMenuTrigger asChild><Button type="button" variant="outline" size="icon" aria-label={l('Result actions', 'Tindakan hasil')}><Ellipsis className="size-4" /></Button></DropdownMenuTrigger><DropdownMenuContent align="end"><DropdownMenuItem disabled={!job.address} onSelect={() => job.address && void copy(job.address)}><Copy className="size-4" />{l('Copy resolved address', 'Salin alamat terselesaikan')}</DropdownMenuItem><DropdownMenuItem onSelect={() => download('portscope-' + job.kind + '-' + job.id + '.json', JSON.stringify(job, null, 2))}>JSON</DropdownMenuItem><DropdownMenuItem onSelect={exportCsv}>CSV</DropdownMenuItem>{job.kind === 'mtr' && <DropdownMenuItem disabled={!job.hops.some(hop => hopHistory(hop)?.length)} onSelect={exportHopCsv}>{l('Hop history CSV', 'CSV riwayat hop')}</DropdownMenuItem>}</DropdownMenuContent></DropdownMenu>
          <Button type="button" variant="outline" size="sm" data-testid="diagnostic-focus-toggle" aria-label={focus ? l('Exit focus view', 'Keluar tampilan fokus') : l('Focus monitoring view', 'Fokus tampilan pemantauan')} aria-pressed={focus} onClick={toggleFocus}>{focus ? <Minimize2 className="size-4" /> : <Maximize2 className="size-4" />}<span className="hidden sm:inline">{focus ? l('Setup', 'Pengaturan') : l('Focus view', 'Tampilan fokus')}</span></Button>
          <Button type="button" variant="outline" size="sm" disabled={!starting && !active(job) || stopping} onClick={() => void stop()}><Square className="size-4" />{l('Stop diagnostic', 'Hentikan diagnostik')}</Button>
        </div>
      </div>
      {focus && (!live || error || job.error || streamStatus === 'reconnecting') && <p role="status" className="shrink-0 rounded-md border px-3 py-2 text-xs text-muted-foreground">{!live ? l('Live paused; cancellation requested.', 'Mode langsung dijeda; pembatalan diminta.') : error || job.error || l('Stream interrupted; reconnecting. Values are last received observations.', 'Aliran terputus; menyambungkan kembali. Nilai adalah pengamatan terakhir.')}</p>}
      {!focus && <Card><CardContent className="space-y-3"><Badge variant={job.reached ? 'secondary' : 'outline'}>{job.reached ? l('Destination responded', 'Tujuan merespons') : l('Destination not confirmed', 'Tujuan belum dikonfirmasi')}</Badge>{job.continuous ? null : <Progress value={job.cycles ? Math.min(100, job.cycle / job.cycles * 100) : 0} aria-label={l('Diagnostic progress', 'Kemajuan diagnostik')} />}<p className="text-xs text-muted-foreground">{new Date(job.startedAt).toLocaleString()} · {formatAge(Date.parse(job.finishedAt || job.updatedAt) - Date.parse(job.startedAt))} · {l('Destination sent / received', 'Tujuan terkirim / diterima')}: {lastHop ? lastHop.sent + ' / ' + lastHop.received : '—'} · {l('Observed loss', 'Kehilangan teramati')}: {lastHop?.sent ? lastHop.lossPercent.toFixed(1) + '%' : '—'}</p>{(job.error || streamStatus === 'reconnecting') && <p className="text-xs text-destructive">{job.error || l('Stream interrupted; reconnecting. Last received observations remain visible.', 'Aliran terputus; menyambungkan kembali. Pengamatan terakhir tetap terlihat.')}</p>}</CardContent></Card>}
      <Tabs value={resultTab} onValueChange={setResultTab} key={job.id} className={cn("min-w-0", focus && "min-h-0 flex-1 overflow-hidden")}>
<TabsList className="max-w-full shrink-0 overflow-x-auto">
<TabsTrigger value="chart">{job.kind === 'mtr' ? l('Selected hop history', 'Riwayat hop terpilih') : l('Response history', 'Riwayat respons')}</TabsTrigger>
<TabsTrigger value="hops">{job.kind === 'mtr' ? l('Hop statistics', 'Statistik hop') : l('Test statistics', 'Statistik uji')}</TabsTrigger>{job.tls && <TabsTrigger value="tls">{l('TLS certificate', 'Sertifikat TLS')}</TabsTrigger>}</TabsList>
<TabsContent value="chart" className={cn(focus && "min-h-0 overflow-hidden")} >
<Card className={cn(focus && "h-full min-h-0 gap-3 py-3")} >
<CardHeader className={cn(focus && "shrink-0 px-4")} >
<CardTitle>{job.kind === 'mtr' ? l('Live per-hop response history', 'Riwayat respons langsung per hop') : l('Observed round-trip / connection time', 'Waktu pulang-pergi / koneksi teramati')}</CardTitle>
<CardDescription className={cn(focus && "hidden")}>{job.kind === 'mtr' ? l('Select one TTL and its current responder. Charts use only that hop’s timestamped backend samples; no cumulative or destination fallback is substituted.', 'Pilih satu TTL dan responder saat ini. Grafik hanya memakai sampel backend bercap waktu hop tersebut; tanpa pengganti kumulatif atau tujuan.') : l('Retained job samples only (up to 240). ICMP replies may be unreachable responses rather than destination success; hover for status. Null gaps are not zero milliseconds.', 'Hanya sampel job tersimpan (hingga 240). Balasan ICMP dapat berupa unreachable, bukan keberhasilan tujuan; arahkan untuk status. Celah null bukan nol milidetik.')}</CardDescription>
</CardHeader>
<CardContent className={cn(focus && "flex min-h-0 flex-1 flex-col px-4")} >
{job.kind === 'mtr' ? <div className={cn("space-y-4", focus && "flex min-h-0 flex-1 flex-col space-y-3")} >
  <Select value={selectedHop ? String(selectedHop.ttl) : ''} onValueChange={value => setSelectedTtl(Number(value))} disabled={!job.hops.length}>
    <SelectTrigger aria-label={l('Hop history', 'Riwayat hop')} className="w-full sm:w-80"><SelectValue placeholder={l('Select an observed hop', 'Pilih hop teramati')} /></SelectTrigger>
    <SelectContent>{job.hops.map(hop => <SelectItem value={String(hop.ttl)} key={hop.ttl}>{l('Hop ', 'Hop ') + hop.ttl + ' · ' + hopLabel(hop.address)}</SelectItem>)}</SelectContent>
  </Select>
  {selectedHop && <div className="flex flex-wrap items-center gap-2"><Badge variant="outline">TTL {selectedHop.ttl}</Badge><span className="break-all font-mono text-xs">{hopLabel(selectedHop.address)}</span><Badge variant="outline">{selectedHop.status}</Badge></div>}
  {selectedSamples?.length ? <HistoryChart key={job.id + ':' + selectedHop!.ttl + ':' + selectedHop!.address} samples={selectedSamples} fit={focus} label={l('History for hop ', 'Riwayat hop ') + selectedHop!.ttl + ' · ' + hopLabel(selectedHop!.address)} testId="diagnostic-hop-chart" /> : <p data-testid="diagnostic-hop-history-empty" className="py-12 text-center text-sm text-muted-foreground">{!selectedHop ? l('Select an observed hop. No history is inferred from destination samples.', 'Pilih hop teramati. Riwayat tidak disimpulkan dari sampel tujuan.') : selectedHop.samples === undefined ? l('This backend did not provide per-hop history. Restart with the updated backend and start a new diagnostic; cumulative statistics cannot be turned into a history.', 'Backend ini tidak menyediakan riwayat per hop. Mulai ulang backend terbaru lalu diagnostik baru; statistik kumulatif tidak dapat diubah menjadi riwayat.') : !selectedHop.address ? l('No responder is known at this TTL. Its history is not attributed to a router.', 'Tidak ada responder diketahui pada TTL ini. Riwayatnya tidak dikaitkan dengan router.') : l('Waiting for real observations from this responder.', 'Menunggu pengamatan nyata dari responder ini.')}</p>}
  <p className={cn("text-xs text-muted-foreground", focus && "sr-only")}>{l('Each TTL is probed independently toward the pinned destination, not by pinging the discovered router IP. Timeouts remain gaps. The backend resets this hop history when the responding IP changes; only the latest 60 observations for the current responder are retained.', 'Setiap TTL diprobe mandiri menuju tujuan terpaku, bukan dengan ping IP router yang ditemukan. Timeout tetap celah. Backend mereset riwayat hop ketika IP responder berubah; hanya 60 pengamatan terbaru responder saat ini disimpan.')}</p>
</div> : job.samples.length ? <HistoryChart samples={job.samples} fit={focus} label={l('Diagnostic response history', 'Riwayat respons diagnostik')} kind={job.kind} testId="diagnostic-chart" /> : <p className="py-12 text-center text-sm text-muted-foreground">{l('Waiting for the first completed probe.', 'Menunggu probe pertama selesai.')}</p>}
<p className={cn("mt-3 text-xs text-muted-foreground", focus && "sr-only")}>{job.timingMethod || l('Timing is reported by the backend for this test, not application request latency.', 'Waktu dilaporkan backend untuk uji ini, bukan latensi permintaan aplikasi.')}</p>
</CardContent>
</Card>
</TabsContent>
      <TabsContent value="hops" className={cn(focus && "min-h-0 overflow-hidden")} >
<Card className={cn(focus && "h-full min-h-0 gap-3 py-3")} >
<CardHeader className={cn(focus && "shrink-0 px-4")} >
<CardTitle className={cn(focus && 'text-sm')}>{job.kind === 'mtr' ? l('Traceroute / MTR hop statistics (ICMP)', 'Statistik hop Traceroute / MTR (ICMP)') : l('Observed test statistics', 'Statistik uji teramati')}</CardTitle>
{focus && <p className="text-xs text-muted-foreground">{l('Times in ms. Intermediate ICMP loss ≠ forwarded loss.', 'Waktu dalam ms. ICMP hilang di tengah ≠ paket terusan hilang.')}<span className="2xl:hidden"> {l('Min/max available in Setup view.', 'Min/maks tersedia pada tampilan Pengaturan.')}</span></p>}
<CardDescription className={cn(focus && "hidden")}>{l('Times in milliseconds. Each row describes its current responder, not a lifetime route: counters reset if the responding IP changes. Jitter is the mean absolute change between successive replies. Missing hops remain unknown.', 'Waktu dalam milidetik. Setiap baris menggambarkan responder saat ini, bukan rute sepanjang waktu: penghitung direset jika IP yang merespons berubah. Jitter adalah rata-rata perubahan absolut antar balasan berurutan. Hop hilang tetap tidak diketahui.')}</CardDescription>
</CardHeader>
<CardContent className={cn(focus && "flex min-h-0 flex-1 flex-col gap-3 px-4")} >
<div ref={hopViewport} data-testid="diagnostic-hop-viewport" className={cn("min-w-0", focus && "min-h-0 flex-1 overflow-auto [&>[data-slot=table-container]]:overflow-visible")} >
<Table data-testid="diagnostic-hop-table" className="text-xs">
<TableHeader>
<TableRow>{['Hop', resolveNames && job.kind === 'mtr' ? l('Host / IP', 'Host / IP') : 'Address', 'Status', 'Sent', 'Recv', 'Loss %', 'Last', 'Min', 'Avg', 'Max', 'Jitter', ...(job.kind === 'mtr' ? [l('Live history', 'Riwayat langsung')] : [])].map(header => <TableHead key={header} className={cn(focus && ['Min', 'Max'].includes(header) && 'hidden 2xl:table-cell')}>{header}</TableHead>)}</TableRow>
</TableHeader>
<TableBody>{visibleHops.map(hop => <TableRow key={hop.ttl} data-hop-ttl={hop.ttl} className={cn(hop.address === job.address && 'bg-muted/40', focus && 'h-10 [&>td]:py-1')}>
<TableCell className="font-mono">{hop.ttl}</TableCell>
<TableCell className="font-mono text-xs">{hopName(hop.address) && <span title={hopName(hop.address)!} className="block max-w-48 truncate font-semibold">{hopName(hop.address)}</span>}<span title={hop.address || undefined} className={cn("block", focus && "max-w-32 truncate", hopName(hop.address) && "text-muted-foreground")}>{hop.address || '—'}</span></TableCell>
<TableCell>
<Badge variant="outline">{hop.status}</Badge>
</TableCell>
<TableCell>{hop.sent}</TableCell>
<TableCell>{hop.received}</TableCell>
<TableCell>{hop.sent ? hop.lossPercent.toFixed(1) : '—'}</TableCell>{[hop.lastMs, hop.minMs, hop.avgMs, hop.maxMs, hop.jitterMs].map((value, index) => <TableCell key={index} className={cn("tabular-nums", focus && [1, 3].includes(index) && "hidden 2xl:table-cell")}>{ms(value)}</TableCell>)}{job.kind === 'mtr' && <TableCell><div className={cn('space-y-1', focus && 'flex items-center gap-2 space-y-0')}>
{hopHistory(hop)?.length ? <HistoryChart key={job.id + ':' + hop.ttl + ':' + hop.address} samples={hopHistory(hop)!} compact dense={focus} label={l('Recent responses for hop ', 'Respons terbaru hop ') + hop.ttl + ' · ' + hopLabel(hop.address)} testId={'diagnostic-hop-sparkline-' + hop.ttl} /> : <span className="text-xs text-muted-foreground">{hop.samples === undefined ? l('History unavailable · restart backend', 'Riwayat tidak tersedia · mulai ulang backend') : !hop.address ? l('No known responder', 'Responder tidak diketahui') : l('Waiting for samples', 'Menunggu sampel')}</span>}
<Button type="button" size="sm" variant="ghost" aria-label={l('View history for hop ', 'Lihat riwayat hop ') + hop.ttl} className={cn(focus && 'size-8 shrink-0 p-0')} onClick={() => { setSelectedTtl(hop.ttl); setResultTab('chart'); }}>{focus ? <Activity className="size-4" /> : l('View history', 'Lihat riwayat')}</Button>
</div></TableCell>}</TableRow>)}</TableBody>
</Table></div>{focus && job.hops.length > 0 && <div className="flex shrink-0 flex-wrap items-center justify-between gap-2"><p data-testid="diagnostic-hop-range" role="status" className="text-xs text-muted-foreground">{l('Hops ', 'Hop ') + (pageStart + 1) + '–' + pageEnd + l(' of ', ' dari ') + job.hops.length}</p><div className="flex items-center gap-2"><Select value={String(currentPage)} onValueChange={value => setHopPage(Number(value))}><SelectTrigger aria-label={l('Hop page', 'Halaman hop')} className="h-8 w-36 text-xs"><SelectValue /></SelectTrigger><SelectContent>{Array.from({ length: pageCount }, (_, index) => <SelectItem value={String(index)} key={index}>{l('Hops ', 'Hop ') + (index * hopPageSize + 1) + '–' + Math.min(job.hops.length, (index + 1) * hopPageSize)}</SelectItem>)}</SelectContent></Select><Button type="button" variant="outline" size="icon" className="size-8" disabled={currentPage === 0} aria-label={l('Previous hops', 'Hop sebelumnya')} onClick={() => setHopPage(currentPage - 1)}><ChevronLeft className="size-4" /></Button><Button type="button" variant="outline" size="icon" className="size-8" disabled={currentPage === pageCount - 1} aria-label={l('Next hops', 'Hop berikutnya')} onClick={() => setHopPage(currentPage + 1)}><ChevronRight className="size-4" /></Button></div></div>}{!job.hops.length && <p className="py-10 text-center text-sm text-muted-foreground">{l('No hop observations received yet.', 'Belum ada pengamatan hop diterima.')}</p>}<Alert className={cn("mt-4", focus && "hidden")}>
<TriangleAlert className="size-4" />
<AlertTitle>{l('Intermediate loss is not necessarily forwarded packet loss', 'Kehilangan perantara belum tentu kehilangan paket terusan')}</AlertTitle>
<AlertDescription>{l('Routers can rate-limit or ignore ICMP while forwarding normally. Read loss end-to-end, compare later hops, and do not infer a broken link or a real-time SLA from one hop. Native ICMP expiry and usable unreachable replies count as responses, not destination success: loss measures missing responses. TCP/TLS are different tests.', 'Router dapat membatasi atau mengabaikan ICMP sambil meneruskan trafik normal. Baca kehilangan ujung-ke-ujung, bandingkan hop berikutnya, jangan simpulkan tautan rusak atau SLA dari satu hop. Balasan ICMP expiry dan unreachable yang dapat digunakan dihitung sebagai respons, bukan keberhasilan tujuan: kehilangan mengukur respons hilang. TCP/TLS adalah uji berbeda.')}</AlertDescription>
</Alert>
</CardContent>
</Card>
</TabsContent>
      {job.tls && <TabsContent value="tls" className={cn(focus && "min-h-0 overflow-auto")} >
<Card>
<CardHeader>
<CardTitle>{l('TLS handshake and peer certificate', 'Handshake TLS dan sertifikat peer')}</CardTitle>
<CardDescription>{l('Certificate verification remains enabled. A self-signed or untrusted certificate is a verification failure, not a successful secure connection.', 'Verifikasi sertifikat tetap aktif. Sertifikat ditandatangani sendiri/tidak tepercaya adalah kegagalan verifikasi, bukan koneksi aman berhasil.')}</CardDescription>
</CardHeader>
<CardContent>
<Alert variant={job.tls.authorized ? 'default' : 'destructive'}>
<ShieldCheck className="size-4" />
<AlertTitle>{job.tls.authorized ? l('Certificate trusted', 'Sertifikat dipercaya') : l('TLS trust verification failed', 'Verifikasi kepercayaan TLS gagal')}</AlertTitle>
<AlertDescription>{job.tls.authorizationError || (job.tls.authorized ? l('Trust and hostname verification passed for this handshake.', 'Verifikasi kepercayaan dan hostname lolos untuk handshake ini.') : l('The server did not provide a verified TLS handshake.', 'Server tidak memberikan handshake TLS terverifikasi.'))}</AlertDescription>
</Alert>
{!job.tls.subject && <p className="mt-3 text-xs text-muted-foreground">{l('Peer certificate details were not available from the rejected or incomplete handshake. Missing fields below are unknown, not evidence of a valid certificate.', 'Detail sertifikat peer tidak tersedia dari handshake ditolak atau belum selesai. Bidang kosong di bawah tidak diketahui, bukan bukti sertifikat valid.')}</p>}
<Table className="mt-4">
<TableBody>{[['Protocol', job.tls.protocol], ['Cipher', job.tls.cipher?.name], ['Server name', job.tls.servername], ['Subject', job.tls.subject ? Object.entries(job.tls.subject).map(([key, value]) => key + '=' + value).join(', ') : null], ['Issuer', job.tls.issuer ? Object.entries(job.tls.issuer).map(([key, value]) => key + '=' + value).join(', ') : null], ['Valid from', job.tls.validFrom], ['Valid to', job.tls.validTo], ['Subject alternative names', job.tls.subjectAltName], ['SHA-256 fingerprint', job.tls.fingerprint256], ['Serial', job.tls.serialNumber]].map(([name, value]) => <TableRow key={name}>
<TableCell className="align-top font-medium">{name}</TableCell>
<TableCell className="max-w-lg break-all whitespace-normal font-mono text-xs">{value || '—'}</TableCell>
</TableRow>)}</TableBody>
</Table>
</CardContent>
</Card>
</TabsContent>}
      </Tabs>
<Accordion type="single" collapsible className={cn(focus && "hidden")}>
<AccordionItem value="limits">
<AccordionTrigger>{l('Interpretation and lifecycle limits', 'Batas penafsiran dan siklus hidup')}</AccordionTrigger>
<AccordionContent>{l('The measurements are active host-origin observations, not browser requests. ICMP support depends on the host OS and native permissions; unsupported platforms return an error rather than simulated data. Closing this workspace, pausing live mode, or pressing Stop requests cancellation. Counted tests have a five-minute ceiling; continuous ICMP monitoring has no time limit while its owner lease is active. Each TTL has an independent cadence and at most one in-flight probe; slower hops do not block faster hops. Resolver selection and live connection discovery never silently start a test.', 'Pengukuran berasal dari host aktif, bukan permintaan peramban. Dukungan ICMP bergantung OS host dan izin native; platform tidak didukung mengembalikan galat, bukan data simulasi. Menutup workspace, menjeda mode langsung atau Stop meminta pembatalan. Uji terhitung dibatasi lima menit; pemantauan ICMP terus-menerus tanpa batas waktu selama lease pemilik aktif. Setiap TTL memiliki irama mandiri dan maksimal satu probe berjalan; hop lambat tidak menghalangi hop cepat. Pemilihan resolver dan penemuan koneksi langsung tidak diam-diam menjalankan uji.')}</AccordionContent>
</AccordionItem>
</Accordion>
    </>}
  </div>;
}
export function diagnosticsSelfCheck() {
  const assert = (condition: unknown, message = 'Diagnostic validation self-check failed') => { if (!condition) throw new Error(message); };
  for (const target of ['127.0.0.1', '::1', '2001:db8::1', 'example.com', 'localhost', 'my-host.test']) assert(validDiagnosticTarget(target));
  for (const target of ['http://host', 'a/b', 'host:443', '999.0.0.1', '0127.0.0.1', 'a..test', '-host', ' x', 'x;whoami', '[::1]', '']) assert(!validDiagnosticTarget(target));
  assert(integer('300', 1, 300) && !integer('301', 1, 300) && !integer('1.5', 1, 300));
  const small = hopPageWindow(500, 32, 0), large = hopPageWindow(2200, 32, 0);
  assert(small.size === 11 && small.pages === 3 && small.start === 0 && small.end === 11, 'Viewport reserves header and readable 40px rows');
  const lastPage = hopPageWindow(500, 32, 99);
  assert(lastPage.page === 2 && lastPage.start === 22 && lastPage.end === 32, 'Last page exposes every remaining hop');
  assert(large.size === 32 && large.pages === 1 && large.end === 32, 'Tall screens can show all 32 hops without shrinking');
  assert(hopPageWindow(500, 32, -4).page === 0 && hopPageWindow(0, 0, NaN).end === 0 && hopPageWindow(NaN, 32, 1).size === 1, 'Resize and empty inputs remain bounded');
  assert(hopPageWindow(500, 32, 0, 80).size === 5 && hopPageWindow(500, 32, 0, 20).size === 11, 'Measured row height can only increase the readability ceiling');
  const seen = Array.from({ length: small.pages }, (_, page) => { const range = hopPageWindow(500, 32, page); return Array.from({ length: range.end - range.start }, (_, index) => range.start + index + 1); }).flat();
  assert(seen.length === 32 && new Set(seen).size === 32 && seen[31] === 32, 'Paging never drops or duplicates a hop');
  for (const height of [1, 240, 400, 500, 800, 2200]) for (const measuredRow of [40, 64, 80, 120]) { const range = hopPageWindow(height, 32, 0, measuredRow); assert(range.size === 1 || 40 + range.size * measuredRow + 2 <= height, 'Visible pages fit their measured viewport at readable row size'); }
  const first: DiagnosticsSample = { at: '2026-01-01T00:00:00.000Z', ms: 0, status: 'success' };
  const timeout: DiagnosticsSample = { at: '2026-01-01T00:00:01.000Z', ms: null, status: 'timeout' };
  const next: DiagnosticsSample = { at: '2026-01-01T00:00:02.000Z', ms: 12, status: 'ttl-expired' };
  const hop: DiagnosticsHop = { ttl: 1, address: '127.0.0.1', status: 'success', sent: 3, received: 2, lost: 1, lossPercent: 100 / 3, lastMs: 12, minMs: 0, avgMs: 6, maxMs: 12, jitterMs: 12, samples: [first, timeout, next] };
  const second: DiagnosticsHop = { ...hop, ttl: 2, address: '127.0.0.2', samples: [{ ...first, at: '2026-01-01T00:00:00.500Z', ms: 80 }] };
  assert(hopHistory(hop)?.length === 3 && hopHistory(second)?.length === 1, 'Independent per-hop histories');
  const addresses = diagnosticHopAddresses([hop, hop, { ...hop, address: null }, { ...hop, address: 'router.example.test' }, { ...hop, address: '999.0.0.1' }, { ...hop, address: '2001:db8::1' }]);
  assert(addresses.join(',') === '127.0.0.1,2001:db8::1', 'Only distinct numeric responder IPs are queried');
  const ptr = { ok: true, source: 'backend', mode: 'reverse', name: hop.address, results: [{ type: 'PTR', status: 'answer', answers: ['router.example.test.'] }] };
  assert(diagnosticPtrName(ptr, hop.address!) === 'router.example.test', 'PTR label strips a terminal DNS root dot');
  assert(diagnosticPtrName({ ...ptr, name: '2001:db8::1' }, '2001:db8::1') === 'router.example.test', 'IPv6 PTR label accepted');
  for (const invalid of [null, {}, { ...ptr, ok: false }, { ...ptr, source: 'browser' }, { ...ptr, mode: 'records' }, { ...ptr, name: '127.0.0.2' }, { ...ptr, results: Array(4).fill(ptr.results[0]) }]) assert(diagnosticPtrName(invalid, hop.address!) === null, 'Mismatched or malformed PTR response keeps the IP');
  for (const answers of [[], ['<script>bad</script>'], ['name with spaces'], ['a'.repeat(64) + '.test'], ['name\n.test'], ['router.test\n'], [42], [{}]]) assert(diagnosticPtrName({ ...ptr, results: [{ ...ptr.results[0], answers }] }, hop.address!) === null, 'Untrusted or absent PTR data never becomes a hostname');
  for (const status of ['nodata', 'error']) assert(diagnosticPtrName({ ...ptr, results: [{ ...ptr.results[0], status }] }, hop.address!) === null, 'DNS failures retain the IP');
  assert(hopHistory(hop)?.[0].ms === 0 && hopHistory(hop)?.[1].ms === null, 'Zero RTT and timeout gaps remain distinct');
  assert(hopHistory({ ...hop, address: null }) === undefined && hopHistory({ ...hop, samples: undefined }) === undefined, 'Never infer unknown or old-backend history');
  const snapshot: DiagnosticsJob = { id: 'check', kind: 'mtr', target: '127.0.0.1', address: '127.0.0.1', family: 4, port: null, status: 'running', startedAt: first.at, updatedAt: next.at, finishedAt: null, error: null, cycle: 1, cycles: null, continuous: true, intervalMs: 1000, timeoutMs: 1000, maxHops: 3, reached: true, timingMethod: 'native', hops: [hop, second], samples: [first] };
  assert(readJob(snapshot).hops[0].samples?.length === 3 && readJob(snapshot).hops[0].samples?.length === 3, 'Repeated snapshots never accumulate samples');
  assert(readJob({ ...snapshot, hops: [{ ...hop, address: '127.0.0.3', samples: [next] }] }).hops[0].samples?.length === 1, 'Responder replacement retains only its supplied history');
  assert(readJob({ ...snapshot, id: 'next-job', hops: [second] }).hops.length === 1, 'New jobs do not inherit prior TTL series');
  assert(readJob({ ...snapshot, continuous: undefined, cycles: 20, hops: [{ ...hop, samples: undefined }] }).cycles === 20, 'Older finite snapshots remain supported');
  const invalidSamples = [[{ ...first, at: 'not-a-date' }], [{ ...first, at: '2026-01-01TInfinity' }], [{ ...first, ms: Infinity }], [{ ...first, ms: -1 }], [{ ...first, status: '' }], Array(61).fill(first)];
  for (const samples of invalidSamples) { assert(!validDiagnosticSamples(samples, 60)); let rejected = false; try { readJob({ ...snapshot, hops: [{ ...hop, samples }] }); } catch { rejected = true; } assert(rejected, 'Reject malformed or oversized hop history'); }
  assert(validDiagnosticSamples(Array(60).fill(first), 60), 'Bounded hop ring accepted');
  for (const invalid of [{ ...snapshot, continuous: true, cycles: 20 }, { ...snapshot, continuous: false, cycles: null }, { ...snapshot, kind: 'tcp' }, { ...snapshot, samples: [{ ...first, at: 'bad' }] }, { ...snapshot, hops: [hop, hop] }, { ...snapshot, hops: [{ ...hop, ttl: 33 }] }]) { let rejected = false; try { readJob(invalid); } catch { rejected = true; } assert(rejected, 'Reject inconsistent continuous jobs or malformed destination samples'); }
  return 'Diagnostic target, continuous mode, independent hop-history and reverse DNS validation checks passed';
}
export default Diagnostics;
