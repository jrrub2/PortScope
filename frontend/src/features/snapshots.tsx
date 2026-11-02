import { useMemo, useRef, useState } from 'react';
import { ArrowDownToLine, ArrowLeftRight, Camera, FileUp, GitCompareArrows, LoaderCircle, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import type { Port, State } from '@/lib/types';
import { download } from '@/lib/utils';
import { getLocale } from '@/lib/i18n';
import { useStorage } from '@/hooks/use-storage';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogTitle } from '@/components/ui/alert-dialog';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

const l = (en: string, id: string) => getLocale() === 'id' ? id : en;
const MAX_BYTES = 2 * 1024 * 1024;
const MAX_PORTS = 2000;
type SnapshotPort = Pick<Port, 'port' | 'protocol' | 'probeStatus' | 'statusCode' | 'pid' | 'processName' | 'bindAddresses' | 'wildcard' | 'framework' | 'title'>;
export interface LocalSnapshot { version: 1; id: string; name: string; capturedAt: string; scannedAt: string; hostname: string; ports: SnapshotPort[] }
function fail(message: string): never { throw new Error(message); }
function object(value: unknown): Record<string, unknown> { return value !== null && typeof value === 'object' && !Array.isArray(value) ? value as Record<string, unknown> : fail('Expected a JSON object.'); }
function keys(value: Record<string, unknown>, allowed: string[]) { if (Object.keys(value).some(key => !allowed.includes(key)) || allowed.some(key => !Object.hasOwn(value, key))) fail('Unexpected or missing snapshot fields.'); }
function text(value: unknown, max: number, nullable = false): string | null { if (nullable && value === null) return null; return typeof value === 'string' && value.length <= max && !/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/.test(value) ? value : fail('Invalid or oversized text field.'); }
function timestamp(value: unknown): string { const at = text(value, 64); return at && /^\d{4}-\d{2}-\d{2}T/.test(at) && Number.isFinite(Date.parse(at)) ? at : fail('Invalid snapshot timestamp.'); }
function pickPort(port: Port): SnapshotPort { return { port: port.port, protocol: port.protocol, probeStatus: port.probeStatus, statusCode: port.statusCode, pid: port.pid, processName: port.processName, bindAddresses: [...port.bindAddresses], wildcard: port.wildcard, framework: port.framework, title: port.title }; }

export function validateSnapshot(value: unknown): LocalSnapshot {
  const item = object(value);
  keys(item, ['version', 'id', 'name', 'capturedAt', 'scannedAt', 'hostname', 'ports']);
  if (item.version !== 1) fail('Unsupported snapshot version; expected 1.');
  const id = text(item.id, 100) || fail('Snapshot ID is required.');
  const name = text(item.name, 80)?.trim() || fail('Snapshot name is required.');
  const capturedAt = timestamp(item.capturedAt), scannedAt = timestamp(item.scannedAt);
  const hostname = text(item.hostname, 255) || fail('Hostname is required.');
  if (!Array.isArray(item.ports) || item.ports.length > MAX_PORTS) fail('Snapshot must contain an array of at most 2000 ports.');
  const seen = new Set<number>();
  const ports = item.ports.map(value => {
    const port = object(value);
    keys(port, ['port', 'protocol', 'probeStatus', 'statusCode', 'pid', 'processName', 'bindAddresses', 'wildcard', 'framework', 'title']);
    if (typeof port.port !== 'number' || !Number.isInteger(port.port) || port.port < 1 || port.port > 65535 || seen.has(port.port)) fail('Invalid or duplicate port number.');
    seen.add(port.port);
    if (typeof port.protocol !== 'string' || !['http', 'https', 'tcp', 'pending'].includes(port.protocol) || typeof port.probeStatus !== 'string' || !['pending', 'done', 'timeout', 'error'].includes(port.probeStatus)) fail('Invalid protocol or probe status.');
    if (port.statusCode !== null && (typeof port.statusCode !== 'number' || !Number.isInteger(port.statusCode) || port.statusCode < 100 || port.statusCode > 599)) fail('Invalid HTTP status.');
    if (typeof port.pid !== 'number' || !Number.isSafeInteger(port.pid) || port.pid < 0) fail('Invalid process ID.');
    if (!Array.isArray(port.bindAddresses) || port.bindAddresses.length > 16 || typeof port.wildcard !== 'boolean') fail('Invalid binding information.');
    return { port: port.port, protocol: port.protocol as SnapshotPort['protocol'], probeStatus: port.probeStatus as SnapshotPort['probeStatus'], statusCode: port.statusCode as number | null, pid: port.pid, processName: text(port.processName, 256, true), bindAddresses: port.bindAddresses.map(address => text(address, 128) || fail('Empty bind address.')), wildcard: port.wildcard, framework: text(port.framework, 128, true), title: text(port.title, 512, true) };
  });
  return { version: 1, id, name, capturedAt, scannedAt, hostname, ports };
}
export function parseSnapshot(content: string): LocalSnapshot { if (new TextEncoder().encode(content).byteLength >= MAX_BYTES) fail('Snapshot files must be smaller than 2 MiB.'); return validateSnapshot(JSON.parse(content)); }
function readSaved(value: unknown) { if (!Array.isArray(value)) return []; const seen = new Set<string>(); return value.slice(0, 10).flatMap(item => { try { const snapshot = validateSnapshot(item); if (seen.has(snapshot.id)) return []; seen.add(snapshot.id); return [snapshot]; } catch { return []; } }); }
export function snapshotCsv(rows: unknown[][]) { return rows.map(row => row.map(value => { let cell = String(value ?? ''); if (/^[\s\u0000-\u001f]*[=+\-@]/.test(cell) || /^[\t\r\n]/.test(cell)) cell = "'" + cell; return '"' + cell.replaceAll('"', '""') + '"'; }).join(',')).join('\r\n'); }
export function diffSnapshotPorts(before: SnapshotPort[], after: SnapshotPort[]) {
  const baseline = new Map(before.map(port => [port.port, port])), current = new Map(after.map(port => [port.port, port]));
  return Array.from(new Set([...baseline.keys(), ...current.keys()])).sort((a, b) => a - b).flatMap(number => {
    const old = baseline.get(number), next = current.get(number);
    const changes = !old ? ['Opened'] : !next ? ['Closed'] : [old.pid !== next.pid || old.processName !== next.processName ? 'Owner' : '', old.protocol !== next.protocol ? 'Protocol' : '', old.statusCode !== next.statusCode || old.probeStatus !== next.probeStatus ? 'Status' : '', old.wildcard !== next.wildcard || [...old.bindAddresses].sort().join('|') !== [...next.bindAddresses].sort().join('|') ? 'Binding' : ''].filter(Boolean);
    return changes.length ? [{ port: number, changes, before: old, after: next }] : [];
  });
}
function describe(port: SnapshotPort | undefined) { return port ? [port.processName || 'Unknown', 'PID ' + port.pid, port.protocol.toUpperCase(), port.statusCode ?? port.probeStatus].join(' · ') : '—'; }
function inventoryCsv(snapshot: LocalSnapshot) { return snapshotCsv([['port', 'protocol', 'probeStatus', 'statusCode', 'pid', 'processName', 'bindAddresses', 'wildcard', 'framework', 'title', 'scannedAt', 'hostname'], ...snapshot.ports.map(port => [port.port, port.protocol, port.probeStatus, port.statusCode, port.pid, port.processName, port.bindAddresses.join('; '), port.wildcard, port.framework, port.title, snapshot.scannedAt, snapshot.hostname])]); }

export function Snapshots({ state }: { state: State }) {
  const [stored, setStored] = useStorage<unknown>('portscope.snapshots.v1', []);
  const saved = useMemo(() => readSaved(stored), [stored]);
  const storageWarning = !Array.isArray(stored) || stored.length !== saved.length;
  const [name, setName] = useState('');
  const [baselineId, setBaselineId] = useState('');
  const [currentId, setCurrentId] = useState('live');
  const [deleting, setDeleting] = useState<LocalSnapshot | null>(null);
  const [error, setError] = useState('');
  const [importing, setImporting] = useState(false);
  const file = useRef<HTMLInputElement>(null);
  const liveAvailable = state.meta.ready && !!state.meta.scannedAt && !state.meta.lastError;
  const live: LocalSnapshot | null = liveAvailable ? { version: 1, id: 'live', name: l('Current live state', 'Kondisi langsung saat ini'), capturedAt: new Date().toISOString(), scannedAt: state.meta.scannedAt!, hostname: state.meta.hostname, ports: state.ports.map(pickPort) } : null;
  const baseline = saved.find(snapshot => snapshot.id === baselineId) ?? saved[0];
  const current = currentId === 'live' ? live : saved.find(snapshot => snapshot.id === currentId) ?? null;
  const changes = baseline && current ? diffSnapshotPorts(baseline.ports, current.ports) : [];
  const showError = (message: string) => { setError(message); toast.error(message); };
  function capture() {
    if (!live || saved.length >= 10 || importing) return;
    try {
      const snapshot = validateSnapshot({ ...live, id: crypto.randomUUID(), name: name.trim() || 'Snapshot ' + new Date().toLocaleString() });
      if (new TextEncoder().encode(JSON.stringify(snapshot)).byteLength >= MAX_BYTES) throw new Error('Snapshot is too large to store.');
      setStored([...saved, snapshot]); setName(''); setError(''); if (!baseline) setBaselineId(snapshot.id);
      toast.success(l('Snapshot captured in this browser', 'Snapshot disimpan di peramban ini'));
    } catch (error) { showError(error instanceof Error ? error.message : 'Snapshot capture failed.'); }
  }
  async function importFile(selected?: File) {
    if (!selected) return;
    setImporting(true); setError('');
    try {
      if (saved.length >= 10) throw new Error(l('Delete a snapshot before importing; the limit is 10.', 'Hapus snapshot sebelum mengimpor; batasnya 10.'));
      if (selected.size >= MAX_BYTES) throw new Error(l('Select a JSON file smaller than 2 MiB.', 'Pilih berkas JSON lebih kecil dari 2 MiB.'));
      const snapshot = { ...parseSnapshot(await selected.text()), id: crypto.randomUUID() };
      setStored([...saved, snapshot]); if (!baseline) setBaselineId(snapshot.id); setCurrentId(snapshot.id);
      toast.success(l('Snapshot imported', 'Snapshot diimpor'));
    } catch (error) { showError(error instanceof Error ? error.message : 'Snapshot import failed.'); }
    finally { setImporting(false); if (file.current) file.current.value = ''; }
  }
  const exportSnapshot = (snapshot: LocalSnapshot, csv = false) => download('portscope-snapshot-' + snapshot.id + (csv ? '.csv' : '.json'), csv ? inventoryCsv(snapshot) : JSON.stringify(snapshot, null, 2), csv ? 'text/csv;charset=utf-8' : 'application/json');
  return <div className="space-y-5">
    <Alert>
<Camera className="size-4" />
<AlertTitle>{l('Browser-local snapshots', 'Snapshot lokal peramban')}</AlertTitle>
<AlertDescription>{l('Up to 10 point-in-time listener inventories are stored only in this browser. Export a copy for durability. Snapshots may contain private process names and addresses; review before sharing.', 'Maksimal 10 inventaris listener sesaat disimpan hanya di peramban ini. Ekspor salinan agar tahan lama. Snapshot bisa berisi nama proses dan alamat privat; tinjau sebelum berbagi.')}</AlertDescription>
</Alert>
    {(error || storageWarning) && <Alert variant="destructive">
<AlertTitle>{l('Snapshot notice', 'Pemberitahuan snapshot')}</AlertTitle>
<AlertDescription>{error || l('Invalid browser-local entries were ignored. Existing valid snapshots remain available; import a trusted export to restore missing data.', 'Entri lokal tidak valid diabaikan. Snapshot valid tetap tersedia; impor ekspor tepercaya untuk memulihkan data.')}</AlertDescription>
</Alert>}
    <Card>
<CardHeader>
<CardTitle>{l('Capture an inventory', 'Ambil inventaris')}</CardTitle>
<CardDescription>{l('Captures the last completed listener scan, never sample data.', 'Menyimpan pemindaian listener terakhir yang selesai, bukan data contoh.')}{state.meta.scannedAt && ' · ' + new Date(state.meta.scannedAt).toLocaleString()}</CardDescription>
</CardHeader>
<CardContent>
<div className="flex flex-wrap items-end gap-3">
<div className="min-w-48 flex-1 space-y-2">
<Label htmlFor="snapshot-name">{l('Snapshot name (optional)', 'Nama snapshot (opsional)')}</Label>
<Input id="snapshot-name" value={name} maxLength={80} onChange={event => setName(event.target.value)} placeholder={l('Before deployment', 'Sebelum deployment')} disabled={importing} />
</div>
<Button onClick={capture} disabled={!live || saved.length >= 10 || importing}>
<Camera className="size-4" />{l('Capture snapshot', 'Simpan snapshot')}</Button>
<Button variant="outline" disabled={saved.length >= 10 || importing} onClick={() => file.current?.click()}>{importing ? <LoaderCircle className="size-4 animate-spin" /> : <FileUp className="size-4" />}{l('Import JSON', 'Impor JSON')}</Button>
<Input ref={file} type="file" accept=".json,application/json" className="hidden" aria-label={l('Import snapshot JSON file', 'Impor berkas JSON snapshot')} onChange={event => void importFile(event.target.files?.[0])} />
</div>
<p className="mt-3 text-xs text-muted-foreground">{saved.length}/10 {l('saved', 'tersimpan')} · {l('Import: schema v1, strictly smaller than 2 MiB, max 2000 ports, no unknown keys.', 'Impor: skema v1, kurang dari 2 MiB, maks. 2000 port, tanpa kunci asing.')}{!liveAvailable && ' · ' + l('Live capture is unavailable until a successful completed scan.', 'Pengambilan langsung belum tersedia hingga pemindaian berhasil selesai.')}{saved.length >= 10 && ' · ' + l('Delete a saved snapshot to make room.', 'Hapus snapshot tersimpan untuk menyediakan ruang.')}</p>
</CardContent>
</Card>
    <Card>
<CardHeader>
<CardTitle className="flex items-center gap-2">
<GitCompareArrows className="size-4" />{l('Compare inventories', 'Bandingkan inventaris')}</CardTitle>
<CardDescription>{l('Port numbers identify listeners. Owner compares PID and process name; PIDs may be reused. Status compares HTTP status and probe state. No CPU, memory or request data is inferred.', 'Nomor port mengidentifikasi listener. Pemilik membandingkan PID dan nama proses; PID bisa dipakai ulang. Status membandingkan status HTTP dan probe. Data CPU, memori atau permintaan tidak disimpulkan.')}</CardDescription>
<div className="flex flex-wrap items-end gap-3">
<div className="min-w-48 flex-1 space-y-2">
<Label>{l('Baseline', 'Baseline')}</Label>
<Select value={baseline?.id ?? ''} onValueChange={setBaselineId}>
<SelectTrigger aria-label={l('Baseline snapshot', 'Snapshot baseline')}>
<SelectValue placeholder={l('Capture a baseline first', 'Ambil baseline dahulu')} />
</SelectTrigger>
<SelectContent>{saved.map(snapshot => <SelectItem value={snapshot.id} key={snapshot.id}>{snapshot.name}</SelectItem>)}</SelectContent>
</Select>
</div>
<div className="min-w-48 flex-1 space-y-2">
<Label>{l('Compare to', 'Bandingkan dengan')}</Label>
<Select value={currentId} onValueChange={setCurrentId}>
<SelectTrigger aria-label={l('Current comparison snapshot', 'Snapshot pembanding')}>
<SelectValue />
</SelectTrigger>
<SelectContent>
<SelectItem value="live">{l('Current live state', 'Kondisi langsung saat ini')}</SelectItem>{saved.map(snapshot => <SelectItem value={snapshot.id} key={snapshot.id}>{snapshot.name}</SelectItem>)}</SelectContent>
</Select>
</div>
<Tooltip>
<TooltipTrigger asChild>
<Button variant="outline" size="icon" aria-label={l('Swap baseline and comparison', 'Tukar baseline dan pembanding')} disabled={!baseline || !current || currentId === 'live'} onClick={() => { if (!baseline || !current) return; setBaselineId(current.id); setCurrentId(baseline.id); }}>
<ArrowLeftRight className="size-4" />
</Button>
</TooltipTrigger>
<TooltipContent>{l('Swap saved inventories', 'Tukar inventaris tersimpan')}</TooltipContent>
</Tooltip>
</div>
</CardHeader>
<CardContent>
      {baseline && current && baseline.hostname !== current.hostname && <Alert className="mb-4">
<AlertTitle>{l('Different hostnames', 'Hostname berbeda')}</AlertTitle>
<AlertDescription>{baseline.hostname} → {current.hostname}. {l('Port/owner differences may reflect different machines, not changes on one host.', 'Perbedaan port/pemilik bisa berasal dari mesin berbeda, bukan perubahan pada satu host.')}</AlertDescription>
</Alert>}
      <Tabs defaultValue="diff">
<TabsList>
<TabsTrigger value="diff">{l('Changes', 'Perubahan')} {baseline && current ? '(' + changes.length + ')' : ''}</TabsTrigger>
<TabsTrigger value="inventory">{l('Current inventory', 'Inventaris pembanding')}</TabsTrigger>
</TabsList>
<TabsContent value="diff">{!baseline || !current ? <div className="py-12 text-center text-sm text-muted-foreground">{!baseline ? l('Capture or import a baseline to compare with current state.', 'Ambil atau impor baseline untuk membandingkan kondisi saat ini.') : l('Comparison data is unavailable; no empty-state diff is assumed.', 'Data pembanding tidak tersedia; tidak diasumsikan sebagai inventaris kosong.')}</div> : <>
<div className="my-4 flex flex-wrap gap-2">{['Opened', 'Closed', 'Owner', 'Protocol', 'Status', 'Binding'].map(change => <Badge variant="outline" key={change}>{change}: {changes.filter(item => item.changes.includes(change)).length}</Badge>)}</div>
<Table>
<TableHeader>
<TableRow>
<TableHead>Port</TableHead>
<TableHead>{l('Change', 'Perubahan')}</TableHead>
<TableHead>{l('Baseline', 'Baseline')}</TableHead>
<TableHead>{l('Comparison', 'Pembanding')}</TableHead>
</TableRow>
</TableHeader>
<TableBody>{changes.map(item => <TableRow key={item.port}>
<TableCell className="font-mono">:{item.port}</TableCell>
<TableCell>
<div className="flex flex-wrap gap-1">{item.changes.map(change => <Badge key={change} variant={change === 'Closed' ? 'outline' : 'secondary'}>{change}</Badge>)}</div>
</TableCell>
<TableCell className="max-w-80 whitespace-normal text-xs">{describe(item.before)}{item.changes.includes('Binding') && <div className="mt-1 font-mono text-muted-foreground">{item.before?.bindAddresses.join(', ') || '—'}</div>}</TableCell>
<TableCell className="max-w-80 whitespace-normal text-xs">{describe(item.after)}{item.changes.includes('Binding') && <div className="mt-1 font-mono text-muted-foreground">{item.after?.bindAddresses.join(', ') || '—'}</div>}</TableCell>
</TableRow>)}</TableBody>
</Table>{!changes.length && <p className="py-10 text-center text-sm text-muted-foreground">{l('No tracked listener fields changed between these inventories.', 'Tidak ada perubahan bidang listener yang dilacak di antara inventaris ini.')}</p>}<div className="mt-4 flex flex-wrap items-center justify-between gap-3 text-xs text-muted-foreground">
<span>{new Date(baseline.scannedAt).toLocaleString()} → {new Date(current.scannedAt).toLocaleString()}</span>
<div className="flex gap-2">
<Button variant="outline" size="sm" onClick={() => download('portscope-diff.json', JSON.stringify({ version: 1, baseline: { id: baseline.id, name: baseline.name, hostname: baseline.hostname, scannedAt: baseline.scannedAt }, current: { id: current.id, name: current.name, hostname: current.hostname, scannedAt: current.scannedAt }, changes }, null, 2))}>JSON</Button>
<Button variant="outline" size="sm" onClick={() => download('portscope-diff.csv', snapshotCsv([['port', 'changes', 'beforePid', 'afterPid', 'beforeProcess', 'afterProcess', 'beforeProtocol', 'afterProtocol', 'beforeStatus', 'afterStatus', 'beforeBinding', 'afterBinding'], ...changes.map(item => [item.port, item.changes.join('; '), item.before?.pid, item.after?.pid, item.before?.processName, item.after?.processName, item.before?.protocol, item.after?.protocol, item.before?.statusCode ?? item.before?.probeStatus, item.after?.statusCode ?? item.after?.probeStatus, item.before?.bindAddresses.join('; '), item.after?.bindAddresses.join('; ')])]), 'text/csv;charset=utf-8')}>CSV</Button>
</div>
</div>
</>}</TabsContent>
<TabsContent value="inventory">{current ? <>
<div className="my-4 flex items-center justify-between gap-3">
<span className="text-sm text-muted-foreground">{current.ports.length} {l('listeners', 'listener')} · {current.hostname}</span>
<div className="flex gap-2">
<Button size="sm" variant="outline" onClick={() => exportSnapshot(current)}>
<ArrowDownToLine className="size-3" />JSON</Button>
<Button size="sm" variant="outline" onClick={() => exportSnapshot(current, true)}>CSV</Button>
</div>
</div>
<Table>
<TableHeader>
<TableRow>
<TableHead>Port</TableHead>
<TableHead>{l('Owner', 'Pemilik')}</TableHead>
<TableHead>{l('Protocol / status', 'Protokol / status')}</TableHead>
<TableHead>{l('Binding', 'Binding')}</TableHead>
</TableRow>
</TableHeader>
<TableBody>{current.ports.map(port => <TableRow key={port.port}>
<TableCell className="font-mono">:{port.port}</TableCell>
<TableCell>{port.processName || '—'}<span className="ml-2 font-mono text-xs text-muted-foreground">PID {port.pid}</span>
</TableCell>
<TableCell>{port.protocol.toUpperCase()} · {port.statusCode ?? port.probeStatus}</TableCell>
<TableCell className="font-mono text-xs">{port.bindAddresses.join(', ') || '—'}</TableCell>
</TableRow>)}</TableBody>
</Table>{!current.ports.length && <p className="py-10 text-center text-sm text-muted-foreground">{l('This completed inventory contains zero listeners.', 'Inventaris selesai ini berisi nol listener.')}</p>}</> : <p className="py-10 text-center text-sm text-muted-foreground">{l('Comparison inventory unavailable.', 'Inventaris pembanding tidak tersedia.')}</p>}</TabsContent>
</Tabs>
    </CardContent>
</Card>
    <Card>
<CardHeader>
<CardTitle>{l('Saved snapshots', 'Snapshot tersimpan')}</CardTitle>
<CardDescription>{l('JSON exports can be imported again. CSV is for spreadsheets and is formula-neutralized, not an import format.', 'Ekspor JSON dapat diimpor kembali. CSV untuk spreadsheet dan dinetralkan dari formula, bukan format impor.')}</CardDescription>
</CardHeader>
<CardContent>
<Table>
<TableHeader>
<TableRow>
<TableHead>{l('Snapshot', 'Snapshot')}</TableHead>
<TableHead>{l('Scan timestamp', 'Waktu pemindaian')}</TableHead>
<TableHead>Ports</TableHead>
<TableHead>{l('Actions', 'Tindakan')}</TableHead>
</TableRow>
</TableHeader>
<TableBody>{saved.map(snapshot => <TableRow key={snapshot.id}>
<TableCell>
<div className="max-w-64 truncate font-medium">{snapshot.name}</div>
<div className="text-xs text-muted-foreground">{snapshot.hostname}</div>
</TableCell>
<TableCell className="text-xs">{new Date(snapshot.scannedAt).toLocaleString()}</TableCell>
<TableCell>{snapshot.ports.length}</TableCell>
<TableCell>
<div className="flex gap-1">
<Button size="sm" variant="ghost" onClick={() => setBaselineId(snapshot.id)}>{l('Baseline', 'Baseline')}</Button>
<Button size="sm" variant="ghost" onClick={() => exportSnapshot(snapshot)}>JSON</Button>
<Button size="sm" variant="ghost" onClick={() => exportSnapshot(snapshot, true)}>CSV</Button>
<Button size="icon" variant="ghost" disabled={importing} aria-label={l('Delete snapshot ', 'Hapus snapshot ') + snapshot.name} onClick={() => setDeleting(snapshot)}>
<Trash2 className="size-4" />
</Button>
</div>
</TableCell>
</TableRow>)}</TableBody>
</Table>{!saved.length && <p className="py-10 text-center text-sm text-muted-foreground">{l('No snapshots saved in this browser yet.', 'Belum ada snapshot tersimpan di peramban ini.')}</p>}</CardContent>
</Card>
    <AlertDialog open={!!deleting} onOpenChange={open => !open && setDeleting(null)}>
<AlertDialogContent>
<AlertDialogHeader>
<AlertDialogTitle>{l('Delete this snapshot?', 'Hapus snapshot ini?')}</AlertDialogTitle>
<AlertDialogDescription>{deleting?.name}. {l('This removes the browser-local copy permanently. Export it first if you need a backup.', 'Salinan lokal peramban akan dihapus permanen. Ekspor dahulu jika perlu cadangan.')}</AlertDialogDescription>
</AlertDialogHeader>
<AlertDialogFooter>
<AlertDialogCancel>{l('Cancel', 'Batal')}</AlertDialogCancel>
<AlertDialogAction onClick={() => { if (!deleting) return; setStored(saved.filter(snapshot => snapshot.id !== deleting.id)); if (currentId === deleting.id) setCurrentId('live'); if (baselineId === deleting.id) setBaselineId(''); setDeleting(null); toast.success(l('Snapshot deleted', 'Snapshot dihapus')); }}>{l('Delete snapshot', 'Hapus snapshot')}</AlertDialogAction>
</AlertDialogFooter>
</AlertDialogContent>
</AlertDialog>
  </div>;
}

// Runnable in a Vite-aware module loader: import { snapshotSelfCheck } and call it.
export function snapshotSelfCheck() {
  const assert = (condition: unknown, message: string) => { if (!condition) throw new Error(message); };
  const port: SnapshotPort = { port: 3000, protocol: 'http', probeStatus: 'done', statusCode: 200, pid: 1, processName: '=formula', bindAddresses: ['127.0.0.1'], wildcard: false, framework: null, title: null };
  const original: LocalSnapshot = { version: 1, id: 'test', name: 'Test', capturedAt: '2026-01-01T00:00:00.000Z', scannedAt: '2026-01-01T00:00:00.000Z', hostname: 'test', ports: [port] };
  assert(parseSnapshot(JSON.stringify(original)).ports.length === 1, 'Valid round trip');
  for (const invalid of [{ ...original, extra: true }, { ...original, ports: [port, port] }, { ...original, ports: [{ ...port, port: 0 }] }, { ...original, ports: [{ ...port, unknown: 1 }] }, { ...original, scannedAt: null }]) { let rejected = false; try { validateSnapshot(invalid); } catch { rejected = true; } assert(rejected, 'Reject malformed snapshot'); }
  const diff = diffSnapshotPorts([port], [{ ...port, pid: 2, protocol: 'https', statusCode: 503 }]);
  assert(diff.length === 1 && diff[0].changes.join(',') === 'Owner,Protocol,Status', 'Report simultaneous field changes');
  assert(diffSnapshotPorts([port], [])[0].changes[0] === 'Closed' && diffSnapshotPorts([], [port])[0].changes[0] === 'Opened', 'Report opened/closed listeners');
  assert(diffSnapshotPorts([port], [port]).length === 0, 'Identical inventory has no changes');
  assert(snapshotCsv([['=1', ' +1', '@evil', 'a"b', 'x,y']]) === `"'=1","' +1","'@evil","a""b","x,y"`, 'Quote CSV and neutralize formulas');
  return 'Snapshot validation, diff and CSV checks passed';
}
export default Snapshots;
