import { useEffect, useId, useMemo, useRef, useState } from 'react';
import { getLocale } from '@/lib/i18n';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Checkbox } from '@/components/ui/checkbox';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';

const l = (en: string, id: string) => getLocale() === 'id' ? id : en;
const MAX_EVENTS = 128, MAX_RESOLVERS = 32, MAX_MESSAGE = 16 * 1024;
const algorithms = [13, 14, 15, 18] as const;
const invalidCases = ['badsig', 'expiredsig', 'nosig'] as const;
type TestCase = 'valid' | typeof invalidCases[number];
type Reach = 'not-run' | 'pending' | 'reached' | 'failed' | 'timeout' | 'cancelled' | 'skipped';
type SecurityResult = { alg: number } & Record<TestCase, Reach>;
type Observation = { time: number; remoteIp: string; remotePort: number; proto: string; qname: string; qtype: string; isEdns0: boolean; udpSize: number | null; clientSubnet: string | null };
const egressEndpoints = [
  { host: 'myip.addr.tools', label: 'IP', family: 0 },
  { host: 'myipv4.addr.tools', label: 'IPv4', family: 4 },
  { host: 'myipv6.addr.tools', label: 'IPv6', family: 6 },
];
type Egress = { host: string; label: string; ip: string | null; outcome: Reach };

// URL supplies the platform IPv6 parser; the IPv4 grammar excludes URL's octal/hex/shorthand forms.
function ipLiteral(value: unknown): string | null {
  if (typeof value !== 'string' || !value || value.length > 45 || /[^0-9a-fA-F:.]/.test(value)) return null;
  const v6 = value.includes(':');
  if (!v6 && !/^(?:0|[1-9][0-9]{0,2})(?:\.(?:0|[1-9][0-9]{0,2})){3}$/.test(value)) return null;
  try {
    const url = new URL('http://' + (v6 ? '[' + value + ']' : value) + '/');
    if (url.username || url.password || url.port || url.pathname !== '/') return null;
    return v6 ? url.hostname.slice(1, -1) : url.hostname === value ? value : null;
  } catch { return null; }
}
function subnetLiteral(value: unknown): string | null {
  if (typeof value !== 'string' || value.length > 49) return null;
  const match = /^([0-9a-fA-F:.]+)\/(0|[1-9][0-9]{0,2})$/.exec(value);
  if (!match) return null;
  const ip = ipLiteral(match[1]), bits = Number(match[2]);
  return ip && bits <= (ip.includes(':') ? 128 : 32) ? ip + '/' + bits : null;
}

// Original adapter for the documented public protocol, not upstream GPL implementation code.
// https://dnscheck.tools/help ; upstream internal/zones/dnscheck/websocket.go
// Compact messages report clientSubnet, NOT ecs; DO/AD are not supplied by this protocol.
function parseObservation(data: unknown, names: ReadonlySet<string>): Observation | null {
  if (typeof data !== 'string' || data.length > MAX_MESSAGE || new TextEncoder().encode(data).byteLength > MAX_MESSAGE) return null;
  try {
    const item: unknown = JSON.parse(data);
    if (!item || typeof item !== 'object' || Array.isArray(item)) return null;
    const r = item as Record<string, unknown>, ip = ipLiteral(r.remoteIp);
    if (!ip || !['UDP', 'TCP', 'TLS', 'QUIC'].includes(r.proto as string) || typeof r.qname !== 'string' || r.qname.length > 254) return null;
    const qname = r.qname.toLowerCase().replace(/\.$/, '');
    if (!/^[a-z0-9.-]+$/.test(qname) || !names.has(qname) || typeof r.qtype !== 'string' || !/^[A-Z][A-Z0-9]{0,15}$/.test(r.qtype)) return null;
    if (!Number.isInteger(r.time) || (r.time as number) < 0 || (r.time as number) > 0xffffffff || !Number.isInteger(r.remotePort) || (r.remotePort as number) < 1 || (r.remotePort as number) > 65535) return null;
    if (r.isEdns0 !== undefined && typeof r.isEdns0 !== 'boolean') return null;
    if (r.udpSize !== undefined && (!Number.isInteger(r.udpSize) || (r.udpSize as number) < 0 || (r.udpSize as number) > 65535 || r.isEdns0 !== true)) return null;
    const clientSubnet = r.clientSubnet === undefined ? null : subnetLiteral(r.clientSubnet);
    if (r.clientSubnet !== undefined && (!clientSubnet || r.isEdns0 !== true)) return null;
    return { time: r.time as number, remoteIp: ip, remotePort: r.remotePort as number, proto: r.proto as string, qname, qtype: r.qtype, isEdns0: r.isEdns0 === true, udpSize: typeof r.udpSize === 'number' ? r.udpSize : null, clientSubnet };
  } catch { return null; }
}
function appendObservation(events: Observation[], event: Observation): Observation[] | null {
  if (events.length >= MAX_EVENTS || (!events.some(item => item.remoteIp === event.remoteIp) && new Set(events.map(item => item.remoteIp)).size >= MAX_RESOLVERS)) return null;
  return [...events, event];
}
function summarize(events: Observation[]) {
  const rows = new Map<string, { ip: string; count: number; transports: Set<string>; edns: number; sizes: Set<number>; subnets: Set<string> }>();
  for (const event of events) {
    let row = rows.get(event.remoteIp);
    if (!row) { row = { ip: event.remoteIp, count: 0, transports: new Set(), edns: 0, sizes: new Set(), subnets: new Set() }; rows.set(event.remoteIp, row); }
    row.count++; row.transports.add(event.proto);
    if (event.isEdns0) row.edns++;
    if (event.udpSize !== null) row.sizes.add(event.udpSize);
    if (event.clientSubnet) row.subnets.add(event.clientSubnet);
  }
  return [...rows.values()];
}
function securityMeaning(control: Reach, result: Reach, alg: number): 'inconclusive' | 'consistent' | 'reached' | 'unsupported-possible' {
  if (control !== 'reached') return 'inconclusive';
  if (result === 'reached') return alg === 18 ? 'unsupported-possible' : 'reached';
  return result === 'failed' ? 'consistent' : 'inconclusive';
}
function reachLabel(result: Reach) {
  switch (result) {
    case 'reached': return l('Endpoint reached', 'Endpoint terjangkau');
    case 'failed': return l('Fetch failed · inconclusive', 'Fetch gagal · belum pasti');
    case 'timeout': return l('Timeout · inconclusive', 'Batas waktu · belum pasti');
    case 'pending': return l('Testing…', 'Menguji…');
    case 'cancelled': return l('Cancelled', 'Dibatalkan');
    case 'skipped': return l('Skipped: control unavailable', 'Dilewati: kontrol tidak tersedia');
    default: return l('Not run', 'Belum dijalankan');
  }
}

export default function BrowserDns({ live }: { live: boolean }) {
  const id = useId();
  const [consent, setConsent] = useState(false), [withEgress, setWithEgress] = useState(false), [withSecurity, setWithSecurity] = useState(false);
  const [running, setRunning] = useState(false), [message, setMessage] = useState('');
  const [events, setEvents] = useState<Observation[]>([]), [rejected, setRejected] = useState(0);
  const [security, setSecurity] = useState<SecurityResult[]>([]), [egress, setEgress] = useState<Egress[]>([]);
  const active = useRef<{ cancel: () => void; finish: (text: string) => void } | null>(null);
  const resolvers = useMemo(() => summarize(events), [events]);

  useEffect(() => () => { active.current?.cancel(); }, []);
  useEffect(() => {
    if (!live) { active.current?.finish(l('Stopped: Live is paused.', 'Dihentikan: Live dijeda.')); setConsent(false); }
  }, [live]);

  function start() {
    if (!live || !consent || active.current) return;
    setEvents([]); setRejected(0); setSecurity([]); setEgress([]);
    let token: string, probes: string[];
    try {
      const random = () => crypto.getRandomValues(new Uint32Array(1))[0].toString(16).padStart(8, '0');
      token = random();
      probes = Array.from({ length: 4 }, (_, i) => 'p' + i + '-' + random() + '.' + token + '-nullip.test.dnscheck.tools');
    } catch { setMessage(l('Unavailable: secure random IDs are not supported.', 'Tidak tersedia: ID acak aman tidak didukung.')); return; }
    const names = new Set<string>(), timers = new Set<number>(), requests = new Set<AbortController>();
    let socket: WebSocket | null = null, opened = false, observed: Observation[] = [], invalid = 0;
    const run = {
      cancel() {
        if (active.current !== run) return;
        active.current = null;
        for (const timer of timers) window.clearTimeout(timer);
        timers.clear();
        for (const request of requests) request.abort();
        requests.clear();
        if (socket) {
          socket.onopen = socket.onmessage = socket.onerror = socket.onclose = null;
          try { socket.close(); } catch { /* Closing an unavailable socket must not prevent request cleanup. */ }
        }
      },
      finish(text: string) {
        if (active.current !== run) return;
        run.cancel(); setRunning(false); setMessage(text);
        setSecurity(previous => previous.map(row => ({ ...row, ...Object.fromEntries((['valid', ...invalidCases] as const).map(key => [key, row[key] === 'pending' ? 'cancelled' : row[key]])) })));
        setEgress(previous => previous.map(row => row.outcome === 'pending' ? { ...row, outcome: 'cancelled' } : row));
      },
    };
    active.current = run; setRunning(true); setMessage(l('Connecting to the authoritative DNScheck observation stream…', 'Menghubungkan aliran observasi otoritatif DNScheck…'));
    function later(action: () => void, ms: number) {
      const timer = window.setTimeout(() => { timers.delete(timer); if (active.current === run) action(); }, ms);
      timers.add(timer); return timer;
    }
    function clear(timer: number) { window.clearTimeout(timer); timers.delete(timer); }
    function updateSecurity(alg: number, key: TestCase, value: Reach) {
      if (active.current === run) setSecurity(previous => previous.map(row => row.alg === alg ? { ...row, [key]: value } : row));
    }
    async function request(url: string, publicIP = false): Promise<{ outcome: Reach; ip?: string }> {
      if (active.current !== run) return { outcome: 'cancelled' };
      const controller = new AbortController(); requests.add(controller);
      let timedOut = false;
      const timer = later(() => { timedOut = true; controller.abort(); }, publicIP ? 5000 : 3000);
      try {
        const response = await fetch(url, { mode: publicIP ? 'cors' : 'no-cors', credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store', redirect: publicIP ? 'error' : 'follow', signal: controller.signal });
        if (!publicIP) return { outcome: active.current === run ? 'reached' : 'cancelled' }; // Opaque resolved responses count; never inspect .ok for no-cors.
        if (!response.ok || !response.body) throw new Error('Unavailable IP response');
        const reader = response.body.getReader(), decoder = new TextDecoder('utf-8', { fatal: true });
        let text = '', size = 0;
        try {
          for (;;) {
            const part = await reader.read();
            if (part.done) break;
            size += part.value.byteLength;
            if (size > 128) throw new Error('Oversized IP response');
            text += decoder.decode(part.value, { stream: true });
          }
          text += decoder.decode();
        } finally { reader.releaseLock(); }
        const ip = ipLiteral(text.trim());
        if (!ip) throw new Error('Invalid IP response');
        return active.current === run ? { outcome: 'reached', ip } : { outcome: 'cancelled' };
      } catch { return { outcome: active.current !== run ? 'cancelled' : timedOut ? 'timeout' : 'failed' }; }
      finally { clear(timer); requests.delete(controller); controller.abort(); }
    }
    function probe(name: string) { names.add(name); return request('https://' + name + '/'); }
    async function work() {
      try {
        setMessage(l('Observing resolver queries. Null-IP probes are expected not to reach an HTTP endpoint.', 'Mengamati kueri resolver. Probe null-IP memang tidak diharapkan menjangkau endpoint HTTP.'));
        await Promise.all(probes.map(probe));
        if (active.current !== run) return;
        if (withEgress) {
          setEgress(egressEndpoints.map(endpoint => ({ ...endpoint, ip: null, outcome: 'pending' })));
          await Promise.all(egressEndpoints.map(async endpoint => {
            const result = await request('https://' + endpoint.host + '/plain', true);
            if (active.current !== run) return;
            const familyOK = result.ip && (!endpoint.family || (result.ip.includes(':') ? 6 : 4) === endpoint.family);
            setEgress(previous => previous.map(row => row.host === endpoint.host ? { ...row, ip: familyOK ? result.ip! : null, outcome: result.outcome === 'reached' && !familyOK ? 'failed' : result.outcome } : row));
          }));
        }
        if (active.current !== run) return;
        if (withSecurity) {
          setSecurity(algorithms.map(alg => ({ alg, valid: 'pending', badsig: 'not-run', expiredsig: 'not-run', nosig: 'not-run' })));
          // Four algorithm workers: each valid control precedes its three invalid probes; at most four requests in flight.
          await Promise.all(algorithms.map(async alg => {
            const control = await probe(token + '.test-alg' + alg + '.dnscheck.tools');
            updateSecurity(alg, 'valid', control.outcome);
            if (active.current !== run) return;
            if (control.outcome !== 'reached') { for (const key of invalidCases) updateSecurity(alg, key, 'skipped'); return; }
            for (const key of invalidCases) {
              if (active.current !== run) return;
              updateSecurity(alg, key, 'pending');
              const result = await probe(token + '-' + key + '.test-alg' + alg + '.dnscheck.tools');
              updateSecurity(alg, key, result.outcome);
            }
          }));
        }
        if (active.current === run) later(() => run.finish(observed.length ? l('Observation complete. These are service-reported, authoritative-side observations only.', 'Observasi selesai. Hasil ini hanya observasi sisi otoritatif yang dilaporkan layanan.') : l('No authoritative queries observed. Results are inconclusive; browser, resolver, network or policy may block probes.', 'Tidak ada kueri otoritatif teramati. Hasil belum pasti; browser, resolver, jaringan, atau kebijakan dapat memblokir probe.')), 5000);
      } catch { run.finish(l('Tests unavailable. Only any observations already received are shown.', 'Pengujian tidak tersedia. Hanya observasi yang sudah diterima yang ditampilkan.')); }
    }
    later(() => run.finish(l('Stopped at the 45-second limit. Partial or unfinished tests are inconclusive.', 'Dihentikan pada batas 45 detik. Pengujian parsial atau belum selesai belum memberi kepastian.')), 45000);
    const connecting = later(() => run.finish(l('DNScheck unavailable: the WebSocket did not open. No browser resolver identification was possible.', 'DNScheck tidak tersedia: WebSocket tidak terbuka. Resolver browser tidak dapat diidentifikasi.')), 5000);
    try {
      socket = new WebSocket('wss://ws.dnscheck.tools/watch/' + token);
      socket.onopen = () => { if (active.current === run) { opened = true; clear(connecting); void work(); } };
      socket.onmessage = ({ data }: MessageEvent<unknown>) => {
        if (active.current !== run) return;
        const event = parseObservation(data, names);
        if (!event) {
          setRejected(++invalid);
          if (invalid >= 16) run.finish(l('Stream stopped after 16 invalid, oversized or unrelated messages.', 'Aliran dihentikan setelah 16 pesan tidak valid, terlalu besar, atau tidak terkait.'));
          return;
        }
        const next = appendObservation(observed, event);
        // ponytail: stop at 128 events / 32 resolver IPs; add paged capture only if sustained monitoring is requested.
        if (!next) { run.finish(l('Stopped at the 32-resolver limit; results are partial.', 'Dihentikan pada batas 32 resolver; hasil bersifat parsial.')); return; }
        observed = next; setEvents(next);
        if (next.length === MAX_EVENTS) run.finish(l('Stopped at the 128-event limit; results are partial.', 'Dihentikan pada batas 128 peristiwa; hasil bersifat parsial.'));
      };
      socket.onerror = socket.onclose = () => run.finish(opened ? l('DNScheck stream interrupted. Any observations shown are partial.', 'Aliran DNScheck terputus. Observasi yang ditampilkan bersifat parsial.') : l('DNScheck unavailable: WebSocket connection failed. No resolver identification; no backend proxy was used.', 'DNScheck tidak tersedia: koneksi WebSocket gagal. Resolver tidak teridentifikasi; tidak ada proxy backend.'));
    } catch { run.finish(l('DNScheck unavailable: WebSocket initialization failed.', 'DNScheck tidak tersedia: inisialisasi WebSocket gagal.')); }
  }

  return <section className="min-w-0 space-y-4" aria-label={l('Browser DNS tests', 'Pengujian DNS browser')}>
    <Card className="min-w-0 overflow-hidden">
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-2"><CardTitle>{l('Browser DNS · optional third-party test', 'DNS browser · pengujian pihak ketiga opsional')}</CardTitle><Badge variant="outline">{running ? l('Running', 'Berjalan') : l('Not running', 'Tidak berjalan')}</Badge></div>
        <CardDescription>{l('Identify resolver IPs that dnscheck.tools sees reaching its authoritative nameservers—not the local OS getServers list. Nothing external runs on mount or automatically repeats.', 'Identifikasi IP resolver yang dilihat dnscheck.tools saat mengakses nameserver otoritatifnya—bukan daftar getServers OS lokal. Tidak ada akses eksternal saat komponen dimuat atau pengulangan otomatis.')}</CardDescription>
      </CardHeader>
      <CardContent className="min-w-0 space-y-4">
        <Alert><AlertTitle>{l('Explicit consent for this visit', 'Persetujuan eksplisit untuk kunjungan ini')}</AlertTitle><AlertDescription id={id + '-privacy'}>{l('dnscheck.tools and addr.tools receive your public IP, resolver IPs, and generated queried names; DNS providers and network intermediaries may also see them. Results remain in this component’s RAM only. HTTP fetches omit credentials and referrer. No backend proxy, STUN, microphone, or local resolver inference.', 'dnscheck.tools dan addr.tools menerima IP publik, IP resolver, dan nama kueri yang dihasilkan; penyedia DNS dan perantara jaringan juga dapat melihatnya. Hasil hanya di RAM komponen ini. Fetch HTTP tanpa kredensial atau referrer. Tanpa proxy backend, STUN, mikrofon, atau inferensi resolver lokal.')}</AlertDescription></Alert>
        <div className="flex items-start gap-3"><Checkbox id={id + '-consent'} checked={consent} aria-describedby={id + '-privacy'} onCheckedChange={value => { setConsent(value === true); if (value !== true) active.current?.finish(l('Stopped: consent withdrawn.', 'Dihentikan: persetujuan dicabut.')); }} /><label htmlFor={id + '-consent'} className="text-sm leading-5">{l('I consent to share this data with dnscheck.tools and addr.tools for this visit.', 'Saya setuju membagikan data ini kepada dnscheck.tools dan addr.tools untuk kunjungan ini.')}</label></div>
        <div className="grid gap-3 pl-7 text-sm">
          <div className="flex items-start gap-3"><Checkbox id={id + '-egress'} checked={withEgress} disabled={running} onCheckedChange={value => setWithEgress(value === true)} /><label htmlFor={id + '-egress'}>{l('Also request public HTTP egress IPs from myip / myipv4 / myipv6.addr.tools (up to 5s each).', 'Minta juga IP egress HTTP publik dari myip / myipv4 / myipv6.addr.tools (maksimal 5 detik per permintaan).')}</label></div>
          <div className="flex items-start gap-3"><Checkbox id={id + '-security'} checked={withSecurity} disabled={running} onCheckedChange={value => setWithSecurity(value === true)} /><label htmlFor={id + '-security'}>{l('Also probe DNSSEC reachability: algorithms 13, 14, 15, 18; valid controls then badsig / expiredsig / nosig (up to 16 fetches, concurrency 4).', 'Uji juga keterjangkauan DNSSEC: algoritme 13, 14, 15, 18; kontrol valid lalu badsig / expiredsig / nosig (maksimal 16 fetch, konkurensi 4).')}</label></div>
        </div>
        <div className="flex flex-wrap items-center gap-2"><Button type="button" disabled={!live || !consent || running} onClick={start}>{l('Run tests', 'Jalankan pengujian')}</Button><Button type="button" variant="outline" disabled={!running} onClick={() => active.current?.finish(l('Stopped by you; any observations are partial.', 'Dihentikan oleh Anda; observasi bersifat parsial.'))}>{l('Stop', 'Hentikan')}</Button><span className="text-xs text-muted-foreground">{l('4 harmless null-IP probes · 3s timeout · 45s maximum run', '4 probe null-IP aman · batas waktu 3 detik · maksimal 45 detik')}</span></div>
        {!live && <p className="text-sm text-muted-foreground">{l('Live is paused. Active tests are cancelled; enable Live and consent before running.', 'Live dijeda. Pengujian aktif dibatalkan; aktifkan Live dan persetujuan sebelum menjalankan.')}</p>}
        <p role="status" aria-live="polite" className="text-sm">{message || l('No external requests sent. Choose options, consent, then run.', 'Belum ada permintaan eksternal. Pilih opsi, beri persetujuan, lalu jalankan.')}</p>
      </CardContent>
    </Card>

    <Card className="min-w-0 overflow-hidden">
      <CardHeader><CardTitle>{l('Authoritative-observed resolvers', 'Resolver yang teramati di sisi otoritatif')} <Badge variant="secondary">{resolvers.length}/{MAX_RESOLVERS}</Badge></CardTitle><CardDescription>{l('These can be upstream/forwarding resolvers, not the browser’s immediate resolver. Transports are resolver → authoritative only; they do not reveal browser → resolver encryption. IPv6 means an observed IPv6 source—not a client IPv6 capability test.', 'Ini bisa berupa resolver upstream/penerus, bukan resolver terdekat browser. Transport hanya resolver → otoritatif; tidak mengungkap enkripsi browser → resolver. IPv6 berarti sumber IPv6 teramati—bukan pengujian kemampuan IPv6 klien.')}</CardDescription></CardHeader>
      <CardContent className="min-w-0 space-y-3">
        <div className="max-w-full overflow-hidden rounded-md border"><Table aria-label={l('Observed resolver summary', 'Ringkasan resolver teramati')} className="min-w-[680px]"><TableHeader><TableRow><TableHead>{l('Resolver IP', 'IP resolver')}</TableHead><TableHead>{l('Queries', 'Kueri')}</TableHead><TableHead>{l('Transport / IP', 'Transport / IP')}</TableHead><TableHead>EDNS / UDP</TableHead><TableHead>ECS</TableHead></TableRow></TableHeader><TableBody>
          {!resolvers.length && <TableRow><TableCell colSpan={5} className="h-20 whitespace-normal text-center text-muted-foreground">{l('No authoritative resolver observations yet. This is not a clean DNS-leak result.', 'Belum ada observasi resolver otoritatif. Ini bukan hasil bebas kebocoran DNS.')}</TableCell></TableRow>}
          {resolvers.map(row => <TableRow key={row.ip}><TableCell className="font-mono text-xs">{row.ip}</TableCell><TableCell>{row.count}</TableCell><TableCell><div className="flex flex-wrap gap-1">{[...row.transports].map(proto => <Badge variant="outline" key={proto}>{proto}</Badge>)}<Badge variant="secondary">{row.ip.includes(':') ? 'IPv6' : 'IPv4'}</Badge></div></TableCell><TableCell>{row.edns}/{row.count}<div className="text-xs text-muted-foreground">{[...row.sizes].join(', ') || '—'}</div></TableCell><TableCell className="max-w-64 whitespace-normal break-all font-mono text-xs">{[...row.subnets].join(', ') || l('Not observed', 'Tidak teramati')}</TableCell></TableRow>)}
        </TableBody></Table></div>
        <p className="text-xs text-muted-foreground">{l('EDNS shows query counts / total and advertised UDP buffer bytes. ECS is the reported clientSubnet; /0 carries no client prefix. Absence is not a privacy guarantee. Compact upstream messages do not expose DO or AD flags.', 'EDNS menampilkan jumlah kueri / total dan ukuran buffer UDP yang diiklankan dalam byte. ECS adalah clientSubnet yang dilaporkan; /0 tidak membawa prefiks klien. Ketiadaan bukan jaminan privasi. Pesan ringkas upstream tidak menyertakan flag DO atau AD.')}</p>
        {egress.length > 0 && <div className="grid gap-2 border-t pt-3 sm:grid-cols-3">{egress.map(row => <div key={row.host} className="min-w-0"><p className="text-xs text-muted-foreground">HTTP {row.label} · {row.host}</p><p className="break-all font-mono text-xs">{row.ip || (row.outcome === 'reached' ? l('Unavailable', 'Tidak tersedia') : reachLabel(row.outcome))}</p></div>)}<p className="text-xs text-muted-foreground sm:col-span-3">{l('Egress IPs are reported by addr.tools over HTTP, independently of resolver IPs. CORS, blocking or no IPv6 may make them unavailable.', 'IP egress dilaporkan addr.tools melalui HTTP, terpisah dari IP resolver. CORS, pemblokiran, atau tidak adanya IPv6 dapat membuatnya tidak tersedia.')}</p></div>}
      </CardContent>
    </Card>

    {security.length > 0 && <Card className="min-w-0 overflow-hidden"><CardHeader><CardTitle>{l('DNSSEC · reachability-based behavior', 'DNSSEC · perilaku berbasis keterjangkauan')}</CardTitle><CardDescription>{l('No-cors fetches count opaque resolved responses as endpoint reached. A valid control must reach first. Failed invalid fetches can be consistent with validation, but network/TLS/browser policy can also fail: no cryptographic proof or security certification. Timeouts remain inconclusive.', 'Fetch no-cors yang selesai dengan respons opaque dihitung sebagai endpoint terjangkau. Kontrol valid harus terjangkau terlebih dahulu. Fetch tidak valid yang gagal dapat konsisten dengan validasi, tetapi jaringan/TLS/kebijakan browser juga dapat gagal: bukan bukti kriptografi atau sertifikasi keamanan. Batas waktu tetap belum pasti.')}</CardDescription></CardHeader><CardContent className="min-w-0 space-y-3"><div className="max-w-full overflow-hidden rounded-md border"><Table aria-label={l('DNSSEC reachability results', 'Hasil keterjangkauan DNSSEC')} className="min-w-[840px]"><TableHeader><TableRow><TableHead>{l('Algorithm', 'Algoritme')}</TableHead><TableHead>{l('Valid control', 'Kontrol valid')}</TableHead><TableHead>badsig</TableHead><TableHead>expiredsig</TableHead><TableHead>nosig</TableHead></TableRow></TableHeader><TableBody>{security.map(row => <TableRow key={row.alg}><TableCell>alg{row.alg}<div className="text-xs text-muted-foreground">{row.alg === 13 ? 'ECDSA P-256' : row.alg === 14 ? 'ECDSA P-384' : row.alg === 15 ? 'Ed25519' : 'ML-DSA-44'}</div></TableCell><TableCell className="max-w-56 whitespace-normal">{reachLabel(row.valid)}</TableCell>{invalidCases.map(key => { const meaning = securityMeaning(row.valid, row[key], row.alg); return <TableCell key={key} className="max-w-60 whitespace-normal text-xs"><span>{reachLabel(row[key])}</span>{meaning === 'consistent' && <p className="text-muted-foreground">{l('Consistent with validation; not proof.', 'Konsisten dengan validasi; bukan bukti.')}</p>}{meaning === 'reached' && <p className="text-muted-foreground">{l('Validation not demonstrated.', 'Validasi tidak terbukti.')}</p>}{meaning === 'unsupported-possible' && <p className="text-muted-foreground">{key === 'nosig' ? l('Allowed if alg18 is unsupported; not a validation pass.', 'Dapat diterima bila alg18 tidak didukung; bukan lulus validasi.') : l('May reflect unsupported alg18, not a global failure.', 'Mungkin akibat alg18 tidak didukung, bukan kegagalan global.')}</p>}</TableCell>; })}</TableRow>)}</TableBody></Table></div><p className="text-xs text-muted-foreground">{l('Algorithm 18 (ML-DSA-44) is not widely validated. Unsupported algorithms may be treated as insecure, including accepting nosig; do not interpret that alone as a validator defect. This limited adapter does not claim full dnscheck.tools parity.', 'Algoritme 18 (ML-DSA-44) belum banyak divalidasi. Algoritme yang tidak didukung dapat diperlakukan sebagai insecure, termasuk menerima nosig; itu saja tidak membuktikan cacat validator. Adapter terbatas ini tidak mengklaim kesetaraan penuh dengan dnscheck.tools.')}</p></CardContent></Card>}

    <Card className="min-w-0 overflow-hidden"><CardHeader><CardTitle>{l('Authoritative query stream', 'Aliran kueri otoritatif')} <Badge variant="outline">{events.length}/{MAX_EVENTS}</Badge></CardTitle><CardDescription>{l('Bounded to 128 events and 32 resolver IPs, then stops. Only exact names generated by this run are accepted.', 'Dibatasi 128 peristiwa dan 32 IP resolver, lalu berhenti. Hanya nama persis yang dihasilkan oleh pengujian ini yang diterima.')} {rejected > 0 && l('Discarded messages: ', 'Pesan dibuang: ') + rejected}</CardDescription></CardHeader><CardContent className="min-w-0"><div role="region" aria-label={l('Scrollable authoritative query events', 'Peristiwa kueri otoritatif yang dapat digulir')} tabIndex={0} className="max-h-80 max-w-full overflow-auto rounded-md border focus-visible:outline-2 focus-visible:outline-ring"><Table aria-label={l('Authoritative DNS events', 'Peristiwa DNS otoritatif')} className="min-w-[780px]"><TableHeader><TableRow><TableHead>{l('Service time', 'Waktu layanan')}</TableHead><TableHead>{l('Resolver IP', 'IP resolver')}</TableHead><TableHead>{l('Transport', 'Transport')}</TableHead><TableHead>{l('Type', 'Tipe')}</TableHead><TableHead>{l('Queried name', 'Nama kueri')}</TableHead></TableRow></TableHeader><TableBody>{!events.length && <TableRow><TableCell colSpan={5} className="h-20 text-center text-muted-foreground">{l('No events received.', 'Belum ada peristiwa.')}</TableCell></TableRow>}{events.map((event, index) => <TableRow key={index}><TableCell className="text-xs tabular-nums">{new Date(event.time * 1000).toLocaleTimeString()}</TableCell><TableCell className="font-mono text-xs">{event.remoteIp}</TableCell><TableCell>{event.proto}</TableCell><TableCell>{event.qtype}</TableCell><TableCell className="max-w-80 whitespace-normal break-all font-mono text-xs">{event.qname}</TableCell></TableRow>)}</TableBody></Table></div></CardContent></Card>
    <p className="text-xs text-muted-foreground">{l('Protocol references: ', 'Referensi protokol: ')}<a className="underline underline-offset-4" href="https://dnscheck.tools/help" target="_blank" rel="noreferrer noopener">dnscheck.tools help</a> · <a className="underline underline-offset-4" href="https://github.com/brianshea2/addr.tools" target="_blank" rel="noreferrer noopener">addr.tools source</a></p>
  </section>;
}

// Pure, offline check: call browserDnsSelfCheck() with the same TS/VM loader as check-frontend.
// Harness entry: ['features/browser-dns.tsx', 'browserDnsSelfCheck'] (no network or DOM needed).
export function browserDnsSelfCheck() {
  const check = (value: unknown, label: string) => { if (!value) throw new Error('Browser DNS selfcheck: ' + label); };
  check(ipLiteral('192.0.2.1') === '192.0.2.1' && ipLiteral('2001:0DB8::1') === '2001:db8::1', 'platform IP parser');
  for (const value of ['127.1', '2130706433', '0x7f000001', '01.2.3.4', '256.1.1.1', '1.2.3.4/path', '1.2.3.4:80', 'fe80::1%eth0', '1::2::3', 'example.com', '[::1]', '::1@evil.test', ' 1.2.3.4', '1.2.3.4\n']) check(ipLiteral(value) === null, 'reject IP: ' + value);
  check(subnetLiteral('2001:db8::/64') === '2001:db8::/64' && subnetLiteral('0.0.0.0/0') === '0.0.0.0/0', 'ECS prefixes');
  for (const value of ['1.2.3.4/33', '::/129', '1.2.3.4/01', '1.2.3.4', 'x/24']) check(subnetLiteral(value) === null, 'reject ECS');
  const qname = 'p0-01234567.12345678-nullip.test.dnscheck.tools', names = new Set([qname]);
  const base = { time: 1800000000, remoteIp: '2001:db8::1', remotePort: 53000, proto: 'UDP', qname: qname + '.', qtype: 'A', isEdns0: true, udpSize: 1232, clientSubnet: '192.0.2.0/24' };
  const event = parseObservation(JSON.stringify(base), names)!;
  check(event && event.qname === qname && event.clientSubnet === base.clientSubnet && event.isEdns0, 'real compact schema');
  check(parseObservation(JSON.stringify({ ...base, qname: qname.toUpperCase() + '.' }), names), 'canonical DNS name');
  for (const patch of [{ remoteIp: '127.1' }, { proto: 'HTTPS' }, { qname: 'other.' + qname }, { qname: qname + '.evil' }, { qtype: '<script>' }, { time: -1 }, { remotePort: 65536 }, { udpSize: 65536 }, { isEdns0: 'true' }, { clientSubnet: '::/129' }, { isEdns0: false }]) check(parseObservation(JSON.stringify({ ...base, ...patch }), names) === null, 'untrusted schema rejection');
  for (const data of ['{', '[]', 'null', ' '.repeat(MAX_MESSAGE + 1), JSON.stringify({ ...base, ignored: 'é'.repeat(MAX_MESSAGE / 2) }), new Uint8Array(1)]) check(parseObservation(data, names) === null, 'size/type/JSON boundary');
  const noEdns = { time: base.time, remoteIp: '192.0.2.1', remotePort: 53, proto: 'TCP', qname, qtype: 'AAAA' };
  check(parseObservation(JSON.stringify(noEdns), names)?.isEdns0 === false, 'omitted EDNS is not invented');
  let events: Observation[] = [];
  for (let i = 0; i < MAX_EVENTS; i++) events = appendObservation(events, event)!;
  check(events.length === MAX_EVENTS && appendObservation(events, event) === null && summarize(events)[0].count === MAX_EVENTS, '128 event bound and count');
  events = Array.from({ length: MAX_RESOLVERS }, (_, i) => ({ ...event, remoteIp: '192.0.2.' + (i + 1) }));
  check(appendObservation(events, { ...event, remoteIp: '198.51.100.1' }) === null && appendObservation(events, events[0])?.length === 33, '32 resolver bound');
  check(securityMeaning('failed', 'failed', 13) === 'inconclusive' && securityMeaning('reached', 'timeout', 13) === 'inconclusive', 'control and timeout cannot certify');
  check(securityMeaning('reached', 'failed', 13) === 'consistent' && securityMeaning('reached', 'reached', 13) === 'reached' && securityMeaning('reached', 'reached', 18) === 'unsupported-possible', 'reachability and unsupported algorithm nuance');
  return 'Browser DNS: strict IP/schema/session validation, bounded observations, and conservative DNSSEC checks passed';
}
