import { useMemo, useState, type ReactNode } from 'react';
import { Activity, ArrowDownToLine, ArrowUpRight, CalendarDays, Copy, Cpu, Network, Search, ShieldCheck, ShieldEllipsis } from 'lucide-react';
import { Area, AreaChart, Bar, BarChart, CartesianGrid, Cell, XAxis, YAxis } from 'recharts';
import { toast } from 'sonner';
import type { Port, State, NetworkSnapshot, HistorySnapshot } from '@/lib/types';
import { cn, copyText, download, formatAge, formatMs } from '@/lib/utils';
import { getLocale } from '@/lib/i18n';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Calendar } from '@/components/ui/calendar';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { ChartContainer, ChartTooltip, ChartTooltipContent } from '@/components/ui/chart';
import { Input } from '@/components/ui/input';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

const l = (en: string, id: string) => getLocale() === 'id' ? id : en;
const dateTime = (at: string) => new Date(at).toLocaleString();
const endpoint = (address: string | null, port: number | null) => address === null ? '—' : (address.includes(':') ? '[' + address + ']' : address) + (port === null ? '' : ':' + port);
function Empty({ children }: { children: ReactNode }) { return <div className="flex min-h-36 items-center justify-center px-6 py-10 text-center text-sm text-muted-foreground">{children}</div>; }
function Metric({ title, value, note }: { title: string; value: ReactNode; note: string }) { return <Card className="gap-3 py-5">
<CardHeader className="gap-1">
<CardDescription>{title}</CardDescription>
<CardTitle className="text-2xl tabular-nums">{value}</CardTitle>
</CardHeader>
<CardContent className="text-xs text-muted-foreground">{note}</CardContent>
</Card>; }
function SearchBox({ value, onChange, placeholder }: { value: string; onChange: (value: string) => void; placeholder: string }) { return <div className="relative min-w-44 flex-1">
<Search className="pointer-events-none absolute left-3 top-2.5 size-4 text-muted-foreground" />
<Input aria-label={placeholder} placeholder={placeholder} className="pl-9" value={value} onChange={event => onChange(event.target.value)} />
</div>; }
function Choice({ value, onChange, label, options }: { value: string; onChange: (value: string) => void; label: string; options: { value: string; label: string }[] }) { return <Select value={value} onValueChange={onChange}>
<SelectTrigger aria-label={label} className="w-full sm:w-44">
<SelectValue placeholder={label} />
</SelectTrigger>
<SelectContent>{options.map(option => <SelectItem key={option.value} value={option.value}>{option.label}</SelectItem>)}</SelectContent>
</Select>; }
async function copy(value: string) { try { await copyText(value); toast.success(l('Copied to clipboard', 'Disalin ke papan klip')); } catch { toast.error(l('Clipboard access failed', 'Tidak dapat mengakses papan klip')); } }

function Connections({ state, network, onPortSelect }: { state: State; network: NetworkSnapshot | null; onPortSelect: (port: Port) => void }) {
  const [query, setQuery] = useState('');
  const [scope, setScope] = useState('all');
  const [connectionState, setConnectionState] = useState('all');
  const [page, setPage] = useState(0);
  const connections = network?.connections ?? [];
  const filtered = useMemo(() => connections.filter(item => (scope === 'all' || item.scope === scope) && (connectionState === 'all' || item.state === connectionState) && [item.localAddress, item.localPort, item.remoteAddress, item.remotePort, item.pid, item.processName, item.protocol, item.state, item.scope].join(' ').toLowerCase().includes(query.toLowerCase().trim())), [connections, scope, connectionState, query]);
  const pages = Math.max(1, Math.ceil(filtered.length / 100));
  const currentPage = Math.min(page, pages - 1);
  const reset = (setter: (value: string) => void) => (value: string) => { setter(value); setPage(0); };
  return <div className="space-y-5">
    <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
<Metric title={l('Observed sockets', 'Socket teramati')} value={network?.ok ? network.summary.total : '—'} note={l('Passive OS snapshot, not packet capture', 'Snapshot OS pasif, bukan tangkapan paket')} />
<Metric title={l('Established', 'Terhubung')} value={network?.ok ? network.summary.established : '—'} note={l('Current TCP connection state', 'Status koneksi TCP saat ini')} />
<Metric title="Loopback" value={network?.ok ? network.summary.loopback : '—'} note={l('Connections within this host', 'Koneksi di dalam host ini')} />
<Metric title={l('Non-loopback', 'Non-loopback')} value={network?.ok ? network.summary.external : '—'} note={l('Private or public scope; not a threat verdict', 'Lingkup privat/publik; bukan putusan ancaman')} />
</div>
    {network?.limited && <Alert><AlertTitle>{l('Partial connection inventory', 'Inventaris koneksi parsial')}</AlertTitle><AlertDescription>{l('Showing', 'Menampilkan')} {network.connections.length} / {network.totalObserved}. {l('Active sockets are prioritized over listeners and TIME_WAIT; totals describe displayed rows.', 'Socket aktif diprioritaskan sebelum listener dan TIME_WAIT; total menghitung baris yang ditampilkan.')}</AlertDescription></Alert>}
    {(!network || !network.ok || network.error) && <Alert>
<Network className="size-4" />
<AlertTitle>{l('Network observation', 'Pengamatan jaringan')}</AlertTitle>
<AlertDescription>{network?.error || l('Waiting for a network snapshot. Connections are not inferred from listener ports.', 'Menunggu snapshot jaringan. Koneksi tidak disimpulkan dari port listener.')}</AlertDescription>
</Alert>}
    <Tabs defaultValue="connections">
<TabsList>
<TabsTrigger value="connections">{l('Connections', 'Koneksi')}</TabsTrigger>
<TabsTrigger value="interfaces">{l('Interfaces', 'Antarmuka')} {network ? '(' + network.interfaces.length + ')' : ''}</TabsTrigger>
</TabsList>
      <TabsContent value="connections">
<Card>
<CardHeader>
<CardTitle>{l('Connection inventory', 'Inventaris koneksi')}</CardTitle>
<CardDescription>{l('Local and remote endpoints reported by the operating system. Scope describes the remote address, not reachability.', 'Endpoint lokal dan jarak jauh dari sistem operasi. Lingkup menjelaskan alamat tujuan, bukan keterjangkauan.')}{network?.scannedAt && ' · ' + dateTime(network.scannedAt)}</CardDescription>
</CardHeader>
<CardContent>
        <div className="mb-4 flex flex-wrap gap-2">
<SearchBox value={query} onChange={reset(setQuery)} placeholder={l('Search address, port, PID…', 'Cari alamat, port, PID…')} />
<Choice value={scope} onChange={reset(setScope)} label="Scope" options={['all', 'loopback', 'private', 'public', 'unknown'].map(value => ({ value, label: value === 'all' ? l('All scopes', 'Semua lingkup') : value }))} />
<Choice value={connectionState} onChange={reset(setConnectionState)} label={l('Connection state', 'Status koneksi')} options={[{ value: 'all', label: l('All states', 'Semua status') }, ...Array.from(new Set(connections.map(item => item.state))).sort().map(value => ({ value, label: value }))]} />
</div>
        <Table>
<TableHeader>
<TableRow>
<TableHead>{l('Local endpoint', 'Endpoint lokal')}</TableHead>
<TableHead>{l('Remote endpoint', 'Endpoint tujuan')}</TableHead>
<TableHead>{l('State / scope', 'Status / lingkup')}</TableHead>
<TableHead>{l('Process', 'Proses')}</TableHead>
<TableHead>PID</TableHead>
<TableHead>
<span className="sr-only">{l('Details', 'Detail')}</span>
</TableHead>
</TableRow>
</TableHeader>
<TableBody>{filtered.slice(currentPage * 100, currentPage * 100 + 100).map(item => {
          const port = state.ports.find(port => port.port === item.localPort && (item.pid === null || item.pid === port.pid));
          return <TableRow key={item.id}>
<TableCell className="font-mono text-xs">{endpoint(item.localAddress, item.localPort)}<span className="ml-2 text-muted-foreground">{item.protocol.toUpperCase()}</span>
</TableCell>
<TableCell className="font-mono text-xs">{endpoint(item.remoteAddress, item.remotePort)}</TableCell>
<TableCell>
<div className="flex flex-wrap gap-1">
<Badge variant={item.state === 'ESTABLISHED' ? 'secondary' : 'outline'}>{item.state}</Badge>
<Badge variant="outline">{item.scope}</Badge>
</div>
</TableCell>
<TableCell>{item.processName || l('Not reported', 'Tidak dilaporkan')}</TableCell>
<TableCell className="font-mono">{item.pid ?? '—'}</TableCell>
<TableCell>{port && <Tooltip>
<TooltipTrigger asChild>
<Button variant="ghost" size="icon" aria-label={l('Inspect port ', 'Lihat port ') + port.port} onClick={() => onPortSelect(port)}>
<ArrowUpRight className="size-4" />
</Button>
</TooltipTrigger>
<TooltipContent>{l('Inspect local listener', 'Lihat listener lokal')}</TooltipContent>
</Tooltip>}</TableCell>
</TableRow>;
        })}</TableBody>
</Table>
        {!filtered.length && <Empty>{!network ? l('Network snapshot not available yet.', 'Snapshot jaringan belum tersedia.') : !network.ok || network.error ? l('Connection observation is unavailable.', 'Pengamatan koneksi tidak tersedia.') : query || scope !== 'all' || connectionState !== 'all' ? l('No connections match these filters.', 'Tidak ada koneksi yang cocok.') : l('The OS reported no connections in this snapshot.', 'OS tidak melaporkan koneksi dalam snapshot ini.')}</Empty>}
        <div className="mt-4 flex items-center justify-between gap-2 text-xs text-muted-foreground">
<span>{network?.ok ? filtered.length + ' ' + l('matching sockets', 'socket cocok') + ' · ' + (currentPage + 1) + '/' + pages : l('Connection count unavailable', 'Jumlah koneksi tidak tersedia')}</span>
<div className="flex gap-2">
<Button variant="outline" size="sm" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>{l('Previous', 'Sebelumnya')}</Button>
<Button variant="outline" size="sm" disabled={currentPage + 1 >= pages} onClick={() => setPage(currentPage + 1)}>{l('Next', 'Berikutnya')}</Button>
</div>
</div>
      </CardContent>
</Card>
</TabsContent>
      <TabsContent value="interfaces">
<Card>
<CardHeader>
<CardTitle>{l('Host interfaces', 'Antarmuka host')}</CardTitle>
<CardDescription>{l('Local OS interface addresses. No geolocation or active network scan.', 'Alamat antarmuka OS lokal. Tanpa geolokasi atau pemindaian jaringan aktif.')}</CardDescription>
</CardHeader>
<CardContent>
<Table>
<TableHeader>
<TableRow>
<TableHead>{l('Interface', 'Antarmuka')}</TableHead>
<TableHead>{l('Address', 'Alamat')}</TableHead>
<TableHead>{l('Network', 'Jaringan')}</TableHead>
<TableHead>MAC</TableHead>
<TableHead>{l('Copy', 'Salin')}</TableHead>
</TableRow>
</TableHeader>
<TableBody>{network?.interfaces.map((item, index) => <TableRow key={item.name + item.address + index}>
<TableCell>
<div className="font-medium">{item.name}</div>
<div className="mt-1 flex gap-1">
<Badge variant="outline">{item.family}</Badge>{item.internal && <Badge variant="secondary">Loopback</Badge>}</div>
</TableCell>
<TableCell className="font-mono text-xs">{item.address}</TableCell>
<TableCell className="font-mono text-xs">{item.cidr || item.netmask || '—'}</TableCell>
<TableCell className="font-mono text-xs">{item.mac || '—'}</TableCell>
<TableCell>
<Button variant="ghost" size="icon" aria-label={l('Copy address ', 'Salin alamat ') + item.address} onClick={() => void copy(item.address)}>
<Copy className="size-4" />
</Button>
</TableCell>
</TableRow>)}</TableBody>
</Table>{!network?.interfaces.length && <Empty>{network?.ok ? l('No interface addresses were reported.', 'Tidak ada alamat antarmuka yang dilaporkan.') : l('Interface snapshot unavailable.', 'Snapshot antarmuka tidak tersedia.')}</Empty>}</CardContent>
</Card>
</TabsContent>
    </Tabs>
  </div>;
}

function Processes({ state, onPortSelect }: { state: State; onPortSelect: (port: Port) => void }) {
  const [query, setQuery] = useState('');
  const locale = getLocale();
  const groups = useMemo(() => {
    const byPid = new Map<number, Port[]>();
    for (const port of state.ports) byPid.set(port.pid, [...(byPid.get(port.pid) ?? []), port]);
    return Array.from(byPid, ([pid, ports]) => ({ pid, ports, name: ports.find(port => port.processName)?.processName || l('Unknown process', 'Proses tidak diketahui') })).sort((a, b) => b.ports.length - a.ports.length || a.pid - b.pid);
  }, [state.ports, locale]);
  const filtered = groups.filter(group => [group.pid, group.name, ...group.ports.map(port => port.port)].join(' ').toLowerCase().includes(query.toLowerCase().trim()));
  return <Card>
<CardHeader>
<div className="flex items-center gap-2">
<Cpu className="size-4 text-muted-foreground" />
<CardTitle>{l('Process ownership', 'Kepemilikan proses')}</CardTitle>
<Badge variant="secondary">{groups.length}</Badge>
</div>
<CardDescription>{l('Listening ports grouped by OS-reported PID. PIDs can be reused; this is a point-in-time view, not process ancestry.', 'Port listener dikelompokkan berdasarkan PID OS. PID dapat dipakai ulang; ini tampilan sesaat, bukan silsilah proses.')}</CardDescription>
<SearchBox value={query} onChange={setQuery} placeholder={l('Search process, PID or port…', 'Cari proses, PID atau port…')} />
</CardHeader>
<CardContent>
<Accordion type="multiple">{filtered.map(group => <AccordionItem key={group.pid} value={String(group.pid)}>
<AccordionTrigger>
<div className="flex min-w-0 flex-wrap items-center gap-x-4 gap-y-2 text-left">
<span className="font-medium">{group.name}</span>
<span className="font-mono text-xs text-muted-foreground">PID {group.pid}</span>
<Badge variant="secondary">{group.ports.length} {l('ports', 'port')}</Badge>
<span className="max-w-56 truncate font-mono text-xs text-muted-foreground">{group.ports.map(port => ':' + port.port).join(' ')}</span>
</div>
</AccordionTrigger>
<AccordionContent>
<Table>
<TableHeader>
<TableRow>
<TableHead>Port</TableHead>
<TableHead>{l('Service', 'Layanan')}</TableHead>
<TableHead>{l('Protocol', 'Protokol')}</TableHead>
<TableHead>{l('Binding', 'Binding')}</TableHead>
<TableHead>{l('Observed latency', 'Latensi teramati')}</TableHead>
<TableHead>{l('Details', 'Detail')}</TableHead>
</TableRow>
</TableHeader>
<TableBody>{group.ports.map(port => <TableRow key={port.port}>
<TableCell className="font-mono">:{port.port}</TableCell>
<TableCell>{port.title || port.framework || '—'}</TableCell>
<TableCell>
<Badge variant="outline">{port.protocol.toUpperCase()}</Badge>
</TableCell>
<TableCell className="font-mono text-xs">{port.bindAddresses.join(', ')}</TableCell>
<TableCell>{formatMs(port.responseTimeMs)}</TableCell>
<TableCell>
<Button size="sm" variant="outline" onClick={() => onPortSelect(port)}>{l('Inspect', 'Lihat')}<ArrowUpRight className="size-3" />
</Button>
</TableCell>
</TableRow>)}</TableBody>
</Table>
</AccordionContent>
</AccordionItem>)}</Accordion>{!filtered.length && <Empty>{query ? l('No process matches this search.', 'Tidak ada proses yang cocok.') : state.meta.ready ? l('No listening processes were observed.', 'Tidak ada proses listener teramati.') : l('Waiting for the first scan.', 'Menunggu pemindaian pertama.')}</Empty>}</CardContent>
</Card>;
}

function Exposure({ state, onPortSelect }: { state: State; onPortSelect: (port: Port) => void }) {
  const [query, setQuery] = useState('');
  const [kind, setKind] = useState('all');
  const audits = state.ports.map(port => ({ port, signals: [
    ...(port.wildcard ? [{ kind: 'wildcard', title: l('Wildcard listener', 'Listener wildcard'), detail: l('Bound to every available interface. Firewall rules, routing, address family and authentication still determine who can connect. This does not prove LAN or Internet reachability.', 'Terikat ke semua antarmuka yang tersedia. Firewall, rute, keluarga alamat dan autentikasi tetap menentukan siapa yang bisa terhubung. Ini bukan bukti dapat dijangkau dari LAN/Internet.') }] : []),
    ...(port.protocol === 'http' ? [{ kind: 'http', title: l('Unencrypted HTTP', 'HTTP tanpa enkripsi'), detail: port.wildcard ? l('HTTP was observed on loopback; if this listener is accessible beyond this host, transport data is not encrypted. Consider HTTPS and interface restrictions appropriate to its use.', 'HTTP teramati di loopback; jika listener dapat diakses dari luar host, data transport tidak terenkripsi. Pertimbangkan HTTPS dan pembatasan antarmuka sesuai kebutuhan.') : l('HTTP was observed on loopback. This is common for local development; the observation alone is not evidence of external exposure.', 'HTTP teramati di loopback. Ini umum untuk pengembangan lokal; pengamatan ini bukan bukti paparan eksternal.') }] : []),
    ...(port.category === 'dev' && port.wildcard ? [{ kind: 'dev', title: l('Development service on a wildcard bind', 'Layanan pengembangan pada wildcard'), detail: l('Development tools may expose source, debug endpoints or hot reload. Review bind settings and access controls; framework/category detection is heuristic.', 'Alat pengembangan bisa mengungkap kode, endpoint debug atau hot reload. Tinjau binding dan kontrol akses; deteksi framework/kategori bersifat heuristik.') }] : []),
    ...(port.server || port.poweredBy ? [{ kind: 'disclosure', title: l('Server technology disclosure', 'Pengungkapan teknologi server'), detail: [port.server && 'Server: ' + port.server, port.poweredBy && 'X-Powered-By: ' + port.poweredBy].filter(Boolean).join(' · ') + '. ' + l('Headers reveal implementation hints, not a confirmed vulnerability.', 'Header mengungkap petunjuk implementasi, bukan kerentanan yang terkonfirmasi.') }] : []),
  ] }));
  const filtered = audits.filter(item => item.signals.length && (kind === 'all' || item.signals.some(signal => signal.kind === kind)) && [item.port.port, item.port.pid, item.port.processName, item.port.title, item.port.framework].join(' ').toLowerCase().includes(query.toLowerCase().trim()));
  return <div className="space-y-5">
<Alert>
<ShieldEllipsis className="size-4" />
<AlertTitle>{l('Review signals, not a penetration test', 'Sinyal tinjauan, bukan uji penetrasi')}</AlertTitle>
<AlertDescription>{l('Only local listener metadata and loopback HTTP probes are inspected. Firewall state and external reachability have not been tested. No ports or processes are modified.', 'Hanya metadata listener lokal dan probe HTTP loopback yang diperiksa. Firewall dan keterjangkauan eksternal belum diuji. Port dan proses tidak diubah.')}</AlertDescription>
</Alert>
<div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">{[{ kind: 'wildcard', title: l('Wildcard binds', 'Binding wildcard') }, { kind: 'http', title: l('HTTP listeners', 'Listener HTTP') }, { kind: 'dev', title: l('Wildcard dev services', 'Layanan dev wildcard') }, { kind: 'disclosure', title: l('Technology headers', 'Header teknologi') }].map(item => <Metric key={item.kind} title={item.title} value={audits.filter(audit => audit.signals.some(signal => signal.kind === item.kind)).length} note={l('Observed signal · manual review', 'Sinyal teramati · tinjauan manual')} />)}</div>
<Card>
<CardHeader>
<CardTitle>{l('Exposure audit', 'Audit paparan')}</CardTitle>
<CardDescription>{l('Inspect each listener before deciding whether its configuration is appropriate.', 'Periksa setiap listener untuk menilai kesesuaian konfigurasinya.')}</CardDescription>
<div className="flex flex-wrap gap-2">
<SearchBox value={query} onChange={setQuery} placeholder={l('Search service or port…', 'Cari layanan atau port…')} />
<Choice value={kind} onChange={setKind} label={l('Signal', 'Sinyal')} options={[{ value: 'all', label: l('All signals', 'Semua sinyal') }, { value: 'wildcard', label: 'Wildcard' }, { value: 'http', label: 'HTTP' }, { value: 'dev', label: l('Development', 'Pengembangan') }, { value: 'disclosure', label: l('Disclosure', 'Pengungkapan') }]} />
</div>
</CardHeader>
<CardContent>
<Accordion type="multiple">{filtered.map(({ port, signals }) => <AccordionItem value={String(port.port)} key={port.port}>
<AccordionTrigger>
<div className="flex flex-wrap items-center gap-3 text-left">
<span className="font-mono font-semibold">:{port.port}</span>
<span>{port.title || port.processName || port.protocol.toUpperCase()}</span>
<Badge variant="secondary">{signals.length} {l('signals', 'sinyal')}</Badge>
</div>
</AccordionTrigger>
<AccordionContent>
<div className="space-y-4">{signals.map(signal => <div key={signal.kind} className="border-l-2 border-border pl-4">
<p className="text-sm font-medium">{signal.title}</p>
<p className="mt-1 text-sm text-muted-foreground">{signal.detail}</p>
</div>)}<div className="flex flex-wrap items-center justify-between gap-3">
<span className="font-mono text-xs text-muted-foreground">{port.bindAddresses.join(', ')} · PID {port.pid}</span>
<Button variant="outline" size="sm" onClick={() => onPortSelect(port)}>{l('Inspect listener', 'Lihat listener')}<ArrowUpRight className="size-3" />
</Button>
</div>
</div>
</AccordionContent>
</AccordionItem>)}</Accordion>{!filtered.length && <Empty>
<span className="flex items-center gap-2">
<ShieldCheck className="size-4" />{query || kind !== 'all' ? l('No signals match these filters.', 'Tidak ada sinyal yang cocok.') : state.meta.ready ? l('No selected audit signals observed. This is not a guarantee of security.', 'Tidak ada sinyal audit teramati. Ini bukan jaminan keamanan.') : l('Waiting for the first scan.', 'Menunggu pemindaian pertama.')}</span>
</Empty>}</CardContent>
</Card>
</div>;
}

export function observedLatency(samples: number[]) {
  const sorted = samples.filter(value => Number.isFinite(value) && value >= 0).sort((a, b) => a - b);
  return { count: sorted.length, average: sorted.length ? sorted.reduce((sum, value) => sum + value, 0) / sorted.length : null, p95: sorted.length ? sorted[Math.ceil(sorted.length * .95) - 1] : null };
}
function Analytics({ state, history }: { state: State; history: HistorySnapshot | null }) {
  const [windowSize, setWindowSize] = useState('15');
  const [series, setSeries] = useState('listeners');
  const cutoff = windowSize === 'all' ? 0 : Date.now() - Number(windowSize) * 60_000;
  const samples = history?.samples.filter(sample => Date.parse(sample.at) >= cutoff) ?? [];
  const latency = observedLatency(state.ports.flatMap(port => port.latencyHistory));
  const protocols = ['http', 'https', 'tcp', 'pending'].map((name, index) => ({ name: name.toUpperCase(), count: state.ports.filter(port => port.protocol === name).length, fill: 'var(--chart-' + (index + 1) + ')' })).filter(item => item.count);
  const frameworks = Array.from(state.ports.reduce((map, port) => { const name = port.framework || l('Undetected', 'Tidak terdeteksi'); map.set(name, (map.get(name) ?? 0) + 1); return map; }, new Map<string, number>()), ([name, count]) => ({ name, count })).sort((a, b) => b.count - a.count);
  const chartConfig = { totalPorts: { label: l('Listening ports', 'Port listener'), color: 'var(--chart-1)' }, webPorts: { label: l('HTTP(S)', 'HTTP(S)'), color: 'var(--chart-2)' }, avgResponseTimeMs: { label: l('Mean observed latency (ms)', 'Rata-rata latensi teramati (ms)'), color: 'var(--chart-1)' }, count: { label: l('Listeners', 'Listener'), color: 'var(--chart-1)' } };
  return <div className="space-y-5">
<div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
<Metric title={l('Mean probe latency', 'Rata-rata latensi probe')} value={formatMs(latency.average)} note={latency.count + ' ' + l('retained successful probe samples', 'sampel probe berhasil tersimpan')} />
<Metric title={l('p95 probe latency', 'p95 latensi probe')} value={formatMs(latency.p95)} note={l('Nearest-rank percentile of observed samples', 'Persentil nearest-rank sampel teramati')} />
<Metric title={l('HTTP(S) share', 'Porsi HTTP(S)')} value={state.ports.length ? Math.round(state.ports.filter(port => ['http', 'https'].includes(port.protocol)).length / state.ports.length * 100) + '%' : '—'} note={l('Current listener protocol classification', 'Klasifikasi protokol listener saat ini')} />
<Metric title={l('History samples', 'Sampel riwayat')} value={history ? samples.length : '—'} note={l('Within the selected time window', 'Dalam rentang waktu terpilih')} />
</div>
    <Card>
<CardHeader>
<div className="flex flex-wrap items-center justify-between gap-3">
<div className="space-y-1">
<CardTitle>{l('Session history', 'Riwayat sesi')}</CardTitle>
<CardDescription>{l('In-memory server observations; restarting the server resets this history.', 'Pengamatan server di memori; riwayat ini direset ketika server dimulai ulang.')}</CardDescription>
</div>
<Choice value={windowSize} onChange={setWindowSize} label={l('History window', 'Rentang riwayat')} options={[{ value: '5', label: l('Last 5 minutes', '5 menit terakhir') }, { value: '15', label: l('Last 15 minutes', '15 menit terakhir') }, { value: '60', label: l('Last hour', 'Satu jam terakhir') }, { value: 'all', label: l('All retained history', 'Semua riwayat tersimpan') }]} />
</div>
</CardHeader>
<CardContent>
<Tabs value={series} onValueChange={setSeries}>
<TabsList>
<TabsTrigger value="listeners">{l('Listeners', 'Listener')}</TabsTrigger>
<TabsTrigger value="latency">{l('Latency', 'Latensi')}</TabsTrigger>
</TabsList>
<TabsContent value={series}>{!history?.ok ? <Empty>{l('Session history is unavailable. No sample data is substituted.', 'Riwayat sesi tidak tersedia. Tidak ada data contoh pengganti.')}</Empty> : !samples.length ? <Empty>{l('No observations in this time window yet.', 'Belum ada pengamatan dalam rentang ini.')}</Empty> : <ChartContainer config={chartConfig} className="mt-4 h-64 w-full" aria-label={l('Session observation chart', 'Grafik pengamatan sesi')}>
<AreaChart accessibilityLayer data={samples}>
<CartesianGrid vertical={false} />
<XAxis dataKey="at" tickFormatter={value => new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} minTickGap={40} tickLine={false} axisLine={false} />
<YAxis width={45} tickLine={false} axisLine={false} allowDecimals={series === 'latency'} />
<ChartTooltip content={<ChartTooltipContent labelFormatter={value => dateTime(String(value))} />} />{series === 'listeners' ? <>
<Area type="monotone" dataKey="totalPorts" stroke="var(--color-totalPorts)" fill="var(--color-totalPorts)" fillOpacity={.12} isAnimationActive={false} />
<Area type="monotone" dataKey="webPorts" stroke="var(--color-webPorts)" fill="var(--color-webPorts)" fillOpacity={.1} isAnimationActive={false} />
</> : <Area type="monotone" dataKey="avgResponseTimeMs" stroke="var(--color-avgResponseTimeMs)" fill="var(--color-avgResponseTimeMs)" fillOpacity={.12} connectNulls={false} isAnimationActive={false} />}</AreaChart>
</ChartContainer>}</TabsContent></Tabs><p className="mt-4 text-xs text-muted-foreground">{l('Latency is loopback probe timing, not application request traffic, uptime, or a request SLO. Summary mean/p95 use retained per-listener successful samples without timestamps; the time filter applies only to session charts.', 'Latensi adalah waktu probe loopback, bukan trafik permintaan aplikasi, uptime, atau SLO permintaan. Rata-rata/p95 memakai sampel berhasil per listener tanpa cap waktu; filter waktu hanya berlaku untuk grafik sesi.')}</p>
</CardContent>
</Card>
    <div className="grid gap-5 lg:grid-cols-2">
<Card>
<CardHeader>
<CardTitle>{l('Protocol breakdown', 'Rincian protokol')}</CardTitle>
<CardDescription>{l('Current listeners, not connection traffic', 'Listener saat ini, bukan trafik koneksi')}</CardDescription>
</CardHeader>
<CardContent>{protocols.length ? <ChartContainer config={chartConfig} className="h-56 w-full">
<BarChart accessibilityLayer data={protocols}>
<CartesianGrid vertical={false} />
<XAxis dataKey="name" tickLine={false} axisLine={false} />
<YAxis allowDecimals={false} width={30} tickLine={false} axisLine={false} />
<ChartTooltip content={<ChartTooltipContent />} />
<Bar dataKey="count" radius={4} isAnimationActive={false}>{protocols.map(item => <Cell key={item.name} fill={item.fill} />)}</Bar>
</BarChart>
</ChartContainer> : <Empty>{l('No listeners observed yet.', 'Belum ada listener teramati.')}</Empty>}</CardContent>
</Card>
<Card>
<CardHeader>
<CardTitle>{l('Framework detection', 'Deteksi framework')}</CardTitle>
<CardDescription>{l('Heuristic from probe metadata; undetected does not mean absent', 'Heuristik dari metadata probe; tidak terdeteksi bukan berarti tidak ada')}</CardDescription>
</CardHeader>
<CardContent>{frameworks.length ? <ChartContainer config={chartConfig} className="h-56 w-full">
<BarChart accessibilityLayer data={frameworks.slice(0, 8)} layout="vertical" margin={{ left: 8 }}>
<CartesianGrid horizontal={false} />
<XAxis type="number" allowDecimals={false} hide />
<YAxis dataKey="name" type="category" tickLine={false} axisLine={false} width={110} />
<ChartTooltip content={<ChartTooltipContent />} />
<Bar dataKey="count" fill="var(--color-count)" radius={4} isAnimationActive={false} />
</BarChart>
</ChartContainer> : <Empty>{l('No framework observations yet.', 'Belum ada pengamatan framework.')}</Empty>}{frameworks.length > 8 && <p className="mt-2 text-xs text-muted-foreground">{l('Showing the eight most common classifications.', 'Menampilkan delapan klasifikasi terbanyak.')}</p>}</CardContent>
</Card>
</div>
  </div>;
}

function ActivityLog({ state, onPortSelect }: { state: State; onPortSelect: (port: Port) => void }) {
  const [query, setQuery] = useState('');
  const [type, setType] = useState('all');
  const [day, setDay] = useState<Date>();
  const events = state.events.filter(event => (type === 'all' || type === event.type) && (!day || new Date(event.at).toDateString() === day.toDateString()) && [event.type, event.port, event.pid, event.processName, event.title, event.category].join(' ').toLowerCase().includes(query.toLowerCase().trim()));
  return <Card>
<CardHeader>
<div className="flex flex-wrap items-center justify-between gap-3">
<div className="space-y-1">
<CardTitle className="flex items-center gap-2">
<Activity className="size-4" />{l('Activity journal', 'Jurnal aktivitas')}</CardTitle>
<CardDescription>{l('Bounded server-session listener events. Initial discovery is a baseline, not a burst of opened ports.', 'Peristiwa listener sesi server terbatas. Penemuan awal adalah baseline, bukan lonjakan port baru.')}</CardDescription>
</div>
<Button variant="outline" size="sm" disabled={!events.length} onClick={() => download('portscope-activity-' + new Date().toISOString().slice(0, 10) + '.json', JSON.stringify({ exportedAt: new Date().toISOString(), filters: { query, type, date: day?.toLocaleDateString() ?? null }, events }, null, 2))}>
<ArrowDownToLine className="size-4" />{l('Export filtered', 'Ekspor hasil filter')}</Button>
</div>
<div className="flex flex-wrap gap-2">
<SearchBox value={query} onChange={setQuery} placeholder={l('Search activity…', 'Cari aktivitas…')} />
<Choice value={type} onChange={setType} label={l('Event type', 'Jenis peristiwa')} options={[{ value: 'all', label: l('All event types', 'Semua jenis') }, { value: 'online', label: l('Port opened', 'Port dibuka') }, { value: 'offline', label: l('Port closed', 'Port ditutup') }, { value: 'start', label: l('Session started', 'Sesi dimulai') }]} />
<Popover>
<PopoverTrigger asChild>
<Button variant="outline" className={cn('justify-start', !day && 'text-muted-foreground')}>
<CalendarDays className="size-4" />{day ? day.toLocaleDateString() : l('Filter by date', 'Filter tanggal')}</Button>
</PopoverTrigger>
<PopoverContent className="w-auto p-0" align="end">
<Calendar mode="single" selected={day} onSelect={setDay} />
</PopoverContent>
</Popover>{day && <Button variant="ghost" onClick={() => setDay(undefined)}>{l('Clear date', 'Hapus tanggal')}</Button>}</div>
</CardHeader>
<CardContent>
<Table>
<TableHeader>
<TableRow>
<TableHead>{l('Event', 'Peristiwa')}</TableHead>
<TableHead>Port</TableHead>
<TableHead>{l('Service / process', 'Layanan / proses')}</TableHead>
<TableHead>{l('Observed at', 'Waktu pengamatan')}</TableHead>
<TableHead>{l('Details', 'Detail')}</TableHead>
</TableRow>
</TableHeader>
<TableBody>{events.map(event => { const port = state.ports.find(port => port.port === event.port); return <TableRow key={event.id}>
<TableCell>
<Badge variant={event.type === 'online' ? 'secondary' : 'outline'}>{event.type === 'online' ? l('Opened', 'Dibuka') : event.type === 'offline' ? l('Closed', 'Ditutup') : l('Session started', 'Sesi dimulai')}</Badge>
</TableCell>
<TableCell className="font-mono">{event.port === null ? '—' : ':' + event.port}</TableCell>
<TableCell>
<div>{event.title || event.processName || '—'}</div>{event.title && event.processName && <div className="text-xs text-muted-foreground">{event.processName}</div>}</TableCell>
<TableCell>
<Tooltip>
<TooltipTrigger asChild>
<span className="whitespace-nowrap text-xs" tabIndex={0}>{dateTime(event.at)}</span>
</TooltipTrigger>
<TooltipContent>{formatAge(Date.now() - Date.parse(event.at))} {l('ago', 'lalu')} · {event.at}</TooltipContent>
</Tooltip>
</TableCell>
<TableCell>{port && event.type !== 'offline' && <Button variant="ghost" size="icon" aria-label={l('Inspect port ', 'Lihat port ') + port.port} onClick={() => onPortSelect(port)}>
<ArrowUpRight className="size-4" />
</Button>}</TableCell>
</TableRow>; })}</TableBody>
</Table>{!events.length && <Empty>{query || day || type !== 'all' ? l('No retained activity matches these filters.', 'Tidak ada aktivitas tersimpan yang cocok.') : l('No activity has been recorded in this session yet.', 'Belum ada aktivitas yang direkam dalam sesi ini.')}</Empty>}<p className="mt-4 text-xs text-muted-foreground">{events.length}/{state.events.length} {l('retained events · dates use your browser time zone', 'peristiwa tersimpan · tanggal memakai zona waktu peramban')}</p>
</CardContent>
</Card>;
}

export type InsightsPage = 'connections' | 'processes' | 'exposure' | 'analytics' | 'activity';
export function Insights({ page, state, network = null, history = null, onPortSelect }: { page: InsightsPage; state: State; network?: NetworkSnapshot | null; history?: HistorySnapshot | null; onPortSelect: (port: Port) => void }) {
  if (page === 'connections') return <Connections state={state} network={network} onPortSelect={onPortSelect} />;
  if (page === 'processes') return <Processes state={state} onPortSelect={onPortSelect} />;
  if (page === 'exposure') return <Exposure state={state} onPortSelect={onPortSelect} />;
  if (page === 'analytics') return <Analytics state={state} history={history} />;
  return <ActivityLog state={state} onPortSelect={onPortSelect} />;
}
export default Insights;
