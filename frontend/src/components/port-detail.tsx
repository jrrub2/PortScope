import { useEffect, useMemo, useState } from 'react';
import { ArrowUpRight, Copy, Eye, EyeOff, Loader2, RefreshCw, ShieldAlert, Star, X } from 'lucide-react';
import { CartesianGrid, Line, LineChart, XAxis, YAxis } from 'recharts';
import { toast } from 'sonner';
import type { Port, ProcessDetail } from '@/lib/types';
import { cn, copyText, formatAge, formatMs } from '@/lib/utils';
import { getLocale, t } from '@/lib/i18n';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { ChartContainer, ChartTooltip, ChartTooltipContent } from '@/components/ui/chart';
import { Dialog, DialogClose, DialogContent, DialogDescription, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { ScrollArea } from '@/components/ui/scroll-area';
import { Separator } from '@/components/ui/separator';
import { Skeleton } from '@/components/ui/skeleton';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Textarea } from '@/components/ui/textarea';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';

const l = (en: string, id: string) => getLocale() === 'id' ? id : en;

export function portUrl(port: Port): string | null {
  if (!['http', 'https'].includes(port.protocol) || !Number.isInteger(port.port) || port.port < 1 || port.port > 65535) return null;
  return port.protocol + '://localhost:' + port.port + '/';
}

function Fields({ rows }: { rows: [string, React.ReactNode][] }) {
  return <dl className="grid gap-0 text-sm">{rows.map(([label, value]) => <div key={label} className="grid grid-cols-[minmax(0,1fr)_minmax(0,1.5fr)] gap-4 border-b py-3 last:border-0"><dt className="text-muted-foreground">{label}</dt><dd className="min-w-0 break-words text-right font-medium">{value ?? '—'}</dd></div>)}</dl>;
}

export default function PortDetail({ port, open, onOpenChange, favorite, onFavorite, watched, onWatch, active = true, onClosed }: {
  port: Port | null; open: boolean; onOpenChange: (open: boolean) => void;
  favorite: boolean; onFavorite: (port: number) => void; watched: boolean; onWatch: (port: number) => void;
  active?: boolean; onClosed?: () => void;
}) {
  const [process, setProcess] = useState<ProcessDetail | null>(null);
  const [processError, setProcessError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const [tab, setTab] = useState('overview');
  const [revealHeaders, setRevealHeaders] = useState(false);
  const pid = port?.pid;
  useEffect(() => { if (open) setTab('overview'); setRevealHeaders(false); }, [open, port?.port]);
  useEffect(() => {
    setProcess(null); setProcessError(null); setLoading(false);
    if (!open || !Number.isSafeInteger(pid) || !pid || pid < 1) return;
    const controller = new AbortController();
    setLoading(true);
    void (async () => {
      try {
        const response = await fetch('/api/process/' + pid, { cache: 'no-store', signal: AbortSignal.any([controller.signal, AbortSignal.timeout(12000)]) });
        const data = await response.json();
        if (!response.ok || !data?.ok || !data.process || data.process.pid !== pid) throw new Error(typeof data?.error?.message === 'string' ? data.error.message : t('process.queryFailed') + ' (HTTP ' + response.status + ')');
        const p = data.process;
        const text = (value: unknown) => typeof value === 'string' ? value : null;
        const number = (value: unknown) => typeof value === 'number' && Number.isFinite(value) ? value : null;
        if (!controller.signal.aborted) setProcess({ pid, name: text(p.name), path: text(p.path), commandLine: text(p.commandLine), parentPid: number(p.parentPid), startedAt: text(p.startedAt), workingSetMB: number(p.workingSetMB) });
      } catch (error) { if (!controller.signal.aborted) setProcessError(error instanceof Error ? error.message : t('process.queryFailed')); }
      finally { if (!controller.signal.aborted) setLoading(false); }
    })();
    return () => controller.abort();
  }, [open, pid, attempt]);

  const samples = useMemo(() => (port?.latencyHistory ?? []).filter(value => Number.isFinite(value) && value >= 0).slice(-30).map((latency, index) => ({ sample: index + 1, latency })), [port?.latencyHistory]);
  if (!port) return null;
  const url = portUrl(port);
  const headers = Object.entries(port.headers ?? {});
  const copy = async (text: string) => { try { await copyText(text); toast.success(t('toast.copied')); } catch { toast.error(l('Clipboard unavailable. Copy the address manually.', 'Clipboard tidak tersedia. Salin alamat secara manual.')); } };
  const probe = t('dialog.probe' + ({ done: 'Done', pending: 'Waiting', timeout: 'Timeout', error: 'Failed' }[port.probeStatus] ?? 'Failed'));
  const values = samples.map(sample => sample.latency);

  return <Dialog open={open} onOpenChange={onOpenChange}>
    <DialogContent showCloseButton={false} className="max-h-[92dvh] grid-rows-[auto_minmax(0,1fr)_auto_auto] gap-0 overflow-hidden p-0 sm:max-w-2xl" onCloseAutoFocus={event => { if (onClosed) { event.preventDefault(); onClosed(); } }}>
      <DialogHeader className="border-b px-6 py-5 text-left">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 space-y-2">
            <div className="flex flex-wrap items-center gap-2"><DialogTitle className="text-xl tracking-tight">{t('dialog.title', { port: port.port })}</DialogTitle><Badge variant="secondary" className="font-mono text-[10px] uppercase">{port.protocol}</Badge>{port.isSelf && <Badge variant="outline">{t('dialog.selfBadge')}</Badge>}</div>
            <DialogDescription className="truncate">{port.title || port.processName || l('Local TCP listener', 'Listener TCP lokal')}</DialogDescription>
          </div>
          <DialogClose asChild><Button variant="ghost" size="icon" aria-label={t('dialog.closeAria')}><X className="size-4" /></Button></DialogClose>
        </div>
      </DialogHeader>
      <ScrollArea className="max-h-[min(68vh,650px)] [&>[data-slot=scroll-area-viewport]]:max-h-[min(68vh,650px)]">
        <div className="space-y-5 px-6 py-5">
          {!active && <Alert><ShieldAlert className="size-4" /><AlertDescription>{t('dialog.notActive', { port: port.port })}</AlertDescription></Alert>}
          {processError && <Alert variant="destructive"><ShieldAlert className="size-4" /><AlertTitle>{t('process.unavailable')}</AlertTitle><AlertDescription className="gap-2"><span className="break-words">{processError}</span><Button variant="outline" size="sm" className="w-fit text-foreground" onClick={() => setAttempt(value => value + 1)}><RefreshCw className="size-3.5" />{t('process.retry')}</Button></AlertDescription></Alert>}
          <div className="grid grid-cols-3 divide-x rounded-lg border bg-muted/20 py-4">
            {[[t('dialog.fields.lastLatency'), formatMs(port.responseTimeMs)], [t('dialog.fields.pid'), String(port.pid || '—')], [l('Observed online', 'Teramati online'), formatAge(port.onlineForMs)]].map(([label, value]) => <div key={label} className="min-w-0 px-3 text-center"><p className="truncate text-[11px] text-muted-foreground">{label}</p><p className="mt-1 font-mono text-lg font-semibold tracking-tight">{value}</p></div>)}
          </div>
          <Tabs value={tab} onValueChange={setTab}>
            <TabsList className="mb-2 grid w-full grid-cols-4"><TabsTrigger value="overview">{t('dialog.identity')}</TabsTrigger><TabsTrigger value="headers">{l('Headers', 'Header')} <span className="hidden text-muted-foreground sm:inline">{headers.length}</span></TabsTrigger><TabsTrigger value="process">{t('dialog.process')}</TabsTrigger><TabsTrigger value="latency">{t('table.headers.latency')}</TabsTrigger></TabsList>
            <TabsContent value="overview" className="space-y-5">
              <Fields rows={[[t('table.headers.address'), <span className="font-mono text-xs">{url || 'localhost:' + port.port}</span>], [t('dialog.fields.process'), port.processName], [t('dialog.fields.category'), t('category.' + port.category + 'Long')], [t('dialog.fields.bind'), <span className="font-mono text-xs">{port.bindAddresses.join(', ') || '—'}</span>], [l('Exposure', 'Eksposur'), port.wildcard ? l('Wildcard / all interfaces', 'Wildcard / semua antarmuka') : l('Loopback listener', 'Listener loopback')], [t('dialog.fields.firstSeen'), new Date(port.firstSeenAt).toLocaleString(getLocale())]]} />
              {port.wildcard && <p className="flex gap-2 rounded-md border bg-muted/30 p-3 text-xs leading-relaxed text-muted-foreground"><ShieldAlert className="mt-0.5 size-3.5 shrink-0" />{l('A wildcard bind may expose this service beyond localhost. Actual reachability depends on your firewall and network; this is not a vulnerability verdict.', 'Bind wildcard dapat mengekspos layanan di luar localhost. Akses sebenarnya tergantung firewall dan jaringan; ini bukan kesimpulan kerentanan.')}</p>}
              <div><h3 className="mb-1 text-sm font-semibold">{t('dialog.httpResponse')}</h3><Fields rows={[[t('dialog.fields.status'), port.statusCode != null ? port.statusCode + ' ' + (port.statusText || '') : t('dialog.notHttp')], [t('dialog.fields.server'), port.server], [t('dialog.fields.framework'), port.framework], [t('dialog.fields.poweredBy'), port.poweredBy], [t('dialog.fields.contentType'), port.contentType], [t('dialog.fields.probeStatus'), probe]]} /></div>
              {port.error && <p className="break-words rounded-md border p-3 text-xs text-muted-foreground">{port.error}</p>}
            </TabsContent>
            <TabsContent value="headers" className="space-y-3">
              {headers.some(([key]) => /cookie|authorization|token|secret|(?:^|-)key(?:$|-)/i.test(key)) && <div className="flex items-center justify-between gap-3 rounded-md border bg-muted/20 p-3"><p className="text-[11px] text-muted-foreground">{l('Sensitive response headers are hidden by default.', 'Header respons sensitif disembunyikan secara bawaan.')}</p><Button variant="outline" size="sm" className="h-7 shrink-0 text-[11px]" aria-pressed={revealHeaders} onClick={() => setRevealHeaders(value => !value)}>{revealHeaders ? <EyeOff className="size-3" /> : <Eye className="size-3" />}{revealHeaders ? l('Hide', 'Sembunyikan') : l('Reveal', 'Tampilkan')}</Button></div>}
              {headers.length ? <div className="overflow-hidden rounded-lg border"><Table><TableHeader><TableRow><TableHead>{l('Header', 'Header')}</TableHead><TableHead>{l('Value', 'Nilai')}</TableHead></TableRow></TableHeader><TableBody>{headers.map(([key, value]) => <TableRow key={key}><TableCell className="align-top font-mono text-xs">{key}</TableCell><TableCell className="max-w-72 whitespace-normal break-all font-mono text-xs">{!revealHeaders && /cookie|authorization|token|secret|(?:^|-)key(?:$|-)/i.test(key) ? l('[hidden]', '[disembunyikan]') : value}</TableCell></TableRow>)}</TableBody></Table></div> : <p className="py-14 text-center text-sm text-muted-foreground">{t('dialog.noHeaders')}</p>}
            </TabsContent>
            <TabsContent value="process" className="space-y-4">
              {loading ? <div aria-label={t('process.loading')} className="space-y-3 py-4"><p className="flex items-center gap-2 text-sm text-muted-foreground"><Loader2 className="size-4 animate-spin" />{t('process.loading')}</p><Skeleton className="h-16 w-full" /><Skeleton className="h-24 w-full" /><Skeleton className="h-12 w-2/3" /></div> : process ? <>
                <Fields rows={[[t('dialog.fields.process'), process.name], [t('dialog.fields.pid'), process.pid], [t('process.parentPid'), process.parentPid], [t('process.started'), process.startedAt ? new Date(process.startedAt).toLocaleString(getLocale()) : '—'], [t('process.workingSet'), process.workingSetMB == null ? '—' : process.workingSetMB.toLocaleString(getLocale()) + ' MB']]} />
                <div className="space-y-2"><p className="text-xs font-medium text-muted-foreground">{t('process.path')}</p><Textarea readOnly value={process.path || '—'} aria-label={t('process.path')} rows={2} className="resize-none font-mono text-xs" /></div>
                <div className="space-y-2"><div className="flex items-center justify-between"><p className="text-xs font-medium text-muted-foreground">{t('process.commandLine')}</p>{process.commandLine && <Button variant="ghost" size="sm" onClick={() => void copy(process.commandLine!)}><Copy className="size-3.5" />{l('Copy', 'Salin')}</Button>}</div><Textarea readOnly value={process.commandLine || '—'} aria-label={t('process.commandLine')} rows={4} className="resize-none font-mono text-xs" /></div>
              </> : !processError && <p className="py-12 text-center text-sm text-muted-foreground">{pid ? t('process.unavailable') : t('process.noPid')}</p>}
              <p className="text-xs text-muted-foreground">{l('Loaded on demand from the operating system. Unavailable fields remain blank.', 'Dimuat saat dibuka dari sistem operasi. Kolom yang tidak tersedia tetap kosong.')}</p>
            </TabsContent>
            <TabsContent value="latency" className="space-y-4">
              {samples.length ? <>
                <div className="flex items-center justify-between pt-2"><h3 className="text-sm font-medium">{t('dialog.latency')}</h3><Badge variant="outline">{samples.length} {l('samples', 'sampel')}</Badge></div>
                <ChartContainer config={{ latency: { label: t('table.headers.latency'), color: 'var(--chart-1)' } }} className="h-56 w-full" aria-label={l('Successful HTTP latency samples in milliseconds', 'Sampel latensi HTTP berhasil dalam milidetik')}>
                  <LineChart accessibilityLayer data={samples} margin={{ top: 12, left: -15, right: 8, bottom: 0 }}><CartesianGrid vertical={false} strokeDasharray="3 3" /><XAxis dataKey="sample" tickLine={false} axisLine={false} minTickGap={25} /><YAxis tickLine={false} axisLine={false} width={48} /><ChartTooltip content={<ChartTooltipContent labelFormatter={value => l('Sample ', 'Sampel ') + value} />} /><Line dataKey="latency" type="linear" stroke="var(--color-latency)" strokeWidth={2} dot={samples.length === 1} isAnimationActive={false} /></LineChart>
                </ChartContainer>
                <div className="grid grid-cols-3 gap-3">{[[l('Minimum', 'Minimum'), Math.min(...values)], [l('Average', 'Rata-rata'), values.reduce((sum, value) => sum + value, 0) / values.length], [l('Maximum', 'Maksimum'), Math.max(...values)]].map(([label, value]) => <div key={label} className="rounded-lg border p-3"><p className="text-xs text-muted-foreground">{label}</p><p className="mt-1 font-mono text-base font-semibold">{formatMs(Number(value))}</p></div>)}</div>
                <p className="text-xs leading-relaxed text-muted-foreground">{l('Last successful HTTP probes, oldest to newest. The horizontal axis is a sample index, not a time scale. Failed probes are not plotted.', 'Probe HTTP berhasil terakhir, dari lama ke baru. Sumbu horizontal adalah indeks sampel, bukan skala waktu. Probe gagal tidak diplot.')}</p>
              </> : <p className="py-14 text-center text-sm text-muted-foreground">{t('dialog.noLatency')}</p>}
            </TabsContent>
          </Tabs>
        </div>
      </ScrollArea>
      <Separator />
      <div className="flex flex-wrap items-center justify-between gap-3 bg-muted/15 px-6 py-4">
        <div className="flex gap-1"><Tooltip><TooltipTrigger asChild><Button variant="outline" size="icon" onClick={() => onFavorite(port.port)} aria-label={t(favorite ? 'fav.remove' : 'fav.add', { port: port.port })} aria-pressed={favorite}><Star className={cn('size-4', favorite && 'fill-current')} /></Button></TooltipTrigger><TooltipContent>{t('fav.tooltip')}</TooltipContent></Tooltip><Tooltip><TooltipTrigger asChild><Button variant="outline" size="icon" onClick={() => onWatch(port.port)} aria-pressed={watched} aria-label={watched ? t('watchlist.removeAria', { port: port.port }) : t('watchlist.watchingTitle', { port: port.port })}>{watched ? <EyeOff className="size-4" /> : <Eye className="size-4" />}</Button></TooltipTrigger><TooltipContent>{t('watchlist.title')}</TooltipContent></Tooltip></div>
        <div className="flex gap-2"><Button variant="outline" onClick={() => void copy(url || 'localhost:' + port.port)}><Copy className="size-3.5" />{l('Copy address', 'Salin alamat')}</Button>{url ? <Button asChild><a href={url} target="_blank" rel="noopener noreferrer">{t('dialog.openBrowser')}<ArrowUpRight className="size-4" /></a></Button> : <Button disabled>{t('action.tcpNoUrl')}</Button>}</div>
      </div>
    </DialogContent>
  </Dialog>;
}
