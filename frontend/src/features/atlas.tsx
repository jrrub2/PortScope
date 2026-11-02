import { Component, useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import type { FeatureCollection, LineString, Point } from 'geojson';
import type { GeoJSONSource } from 'maplibre-gl';
import { Compass, Copy, Download, Globe2, LocateFixed, MapPin, Pencil, Plus, ShieldCheck, Trash2, Upload } from 'lucide-react';
import { toast } from 'sonner';
import { Map as MapCanvas, MapArc, MapControls, MapGeoJSON, MapMarker, MapPopup, MarkerContent, MarkerTooltip, useMap, type MapRef, type MapViewport } from '@/components/ui/map';
import { Accordion, AccordionContent, AccordionItem, AccordionTrigger } from '@/components/ui/accordion';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Separator } from '@/components/ui/separator';
import { Switch } from '@/components/ui/switch';
import { Table, TableBody, TableCaption, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip';
import { useStorage } from '@/hooks/use-storage';
import type { GeoResult, NetworkConnection, NetworkSnapshot } from '@/lib/types';
import { cn, copyText, download } from '@/lib/utils';
import localWorld from '@/lib/world-land.json';

type Endpoint = { id: string; name: string; address: string; longitude: number; latitude: number; role: 'origin' | 'endpoint'; source?: 'ipwho.is' };
type Peer = { address: string; connections: NetworkConnection[] };
const MAX_LOOKUPS = 128;
const GEO_BATCH = 8;
type Draft = Omit<Endpoint, 'longitude' | 'latitude'> & { longitude: string; latitude: string };
const MAX_POINTS = 500;
const MAX_BYTES = 1024 * 1024;
const PAGE_SIZE = 25;
const CARTO = {
  light: 'https://basemaps.cartocdn.com/gl/positron-gl-style/style.json',
  dark: 'https://basemaps.cartocdn.com/gl/dark-matter-gl-style/style.json',
};
const initialViewport: MapViewport = { center: [0, 0], zoom: 1, pitch: 0, bearing: 0 };

function host(value: unknown): string {
  if (typeof value !== 'string' || value.length > 320) throw new Error('Address must be a host or IP address, up to 253 characters.');
  let text = value.trim().toLowerCase();
  if (text.startsWith('[') && text.endsWith(']')) text = text.slice(1, -1);
  if (text.includes(':')) {
    if (!/^[a-f0-9:.]+(?:%[a-z0-9_.-]{1,64})?$/.test(text)) throw new Error('Enter an IPv6 address without a port or URL.');
    const [ip, zone] = text.split('%');
    try { return new URL('http://[' + ip + ']/').hostname.slice(1, -1) + (zone ? '%' + zone : ''); }
    catch { throw new Error('Invalid IPv6 address.'); }
  }
  text = text.replace(/\.$/, '');
  if (/^[0-9.]+$/.test(text)) {
    const octets = text.split('.');
    if (octets.length !== 4 || octets.some(part => !/^(0|[1-9][0-9]{0,2})$/.test(part) || Number(part) > 255)) throw new Error('Invalid IPv4 address.');
    return text;
  }
  if (!text || text.length > 253 || text.split('.').some(label => label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label))) throw new Error('Use a hostname or IP only: no scheme, port, path, spaces, or credentials.');
  return text;
}

function maybeHost(value: unknown): string | null {
  try { return host(value); } catch { return null; }
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseInventory(value: unknown): Endpoint[] {
  let rows: unknown;
  if (Array.isArray(value)) rows = value;
  else if (record(value) && value.type === 'FeatureCollection' && Array.isArray(value.features)) {
    if (value.features.length > MAX_POINTS) throw new Error('Maximum 500 endpoints per inventory.');
    rows = value.features.map((feature, index) => {
      if (!record(feature) || feature.type !== 'Feature' || !record(feature.geometry) || feature.geometry.type !== 'Point' || !Array.isArray(feature.geometry.coordinates) || feature.geometry.coordinates.length !== 2 || !record(feature.properties)) throw new Error('GeoJSON feature ' + (index + 1) + ' must be a Point with name, address, and role properties.');
      return { ...feature.properties, id: feature.id ?? feature.properties.id, longitude: feature.geometry.coordinates[0], latitude: feature.geometry.coordinates[1] };
    });
  } else if (record(value) && value.version === 1 && Array.isArray(value.endpoints)) rows = value.endpoints;
  else throw new Error('Use an endpoint array, a version 1 atlas JSON, or a GeoJSON Point FeatureCollection.');
  if (!Array.isArray(rows) || rows.length > MAX_POINTS) throw new Error('Maximum 500 endpoints per inventory.');
  const ids = new Set<string>();
  const addresses = new Set<string>();
  let origins = 0;
  return rows.map((row, index) => {
    if (!record(row)) throw new Error('Endpoint ' + (index + 1) + ' is not an object.');
    const name = typeof row.name === 'string' ? row.name.trim() : '';
    if (!name || name.length > 80 || /[\u0000-\u001f\u007f-\u009f]/.test(name)) throw new Error('Endpoint names must contain 1–80 printable characters.');
    const address = host(row.address);
    const { longitude, latitude, role } = row;
    if (typeof longitude !== 'number' || !Number.isFinite(longitude) || longitude < -180 || longitude > 180 || typeof latitude !== 'number' || !Number.isFinite(latitude) || latitude < -90 || latitude > 90) throw new Error('Coordinates must be finite numbers: longitude −180…180, latitude −90…90.');
    if (role !== 'origin' && role !== 'endpoint') throw new Error('Role must be origin or endpoint.');
    if (role === 'origin' && ++origins > 1) throw new Error('Keep only one origin. Change the existing origin to an endpoint first.');
    const id = row.id === undefined ? 'import-' + index : row.id;
    if (typeof id !== 'string' || !/^[a-zA-Z0-9_-]{1,80}$/.test(id) || ids.has(id)) throw new Error('Endpoint IDs must be unique strings of 1–80 letters, digits, hyphens, or underscores.');
    if (addresses.has(address)) throw new Error('Each address can have only one saved location: ' + address);
    ids.add(id); addresses.add(address);
    return { id, name, address, longitude, latitude, role };
  });
}

function parseImport(text: string): Endpoint[] {
  if (new TextEncoder().encode(text).byteLength > MAX_BYTES) throw new Error('Import is limited to 1 MiB.');
  let value: unknown;
  try { value = JSON.parse(text); } catch { throw new Error('The file is not valid JSON.'); }
  return parseInventory(value);
}

function geojson(points: Endpoint[]): FeatureCollection<Point> {
  return { type: 'FeatureCollection', features: points.map(({ id, name, address, role, longitude, latitude }) => ({ type: 'Feature', id, properties: { id, name, address, role }, geometry: { type: 'Point', coordinates: [longitude, latitude] } })) };
}

function bounds(points: Endpoint[]): [[number, number], [number, number]] {
  const longitudes = points.map(point => point.longitude).sort((a, b) => a - b);
  let gap = -1, start = 0;
  for (let index = 0; index < longitudes.length; index++) {
    const size = (longitudes[(index + 1) % longitudes.length] + (index === longitudes.length - 1 ? 360 : 0)) - longitudes[index];
    if (size > gap) { gap = size; start = (index + 1) % longitudes.length; }
  }
  const west = longitudes[start];
  const east = west + 360 - gap;
  return [[west, Math.max(-85, Math.min(85, Math.min(...points.map(point => point.latitude))))], [east, Math.max(-85, Math.min(85, Math.max(...points.map(point => point.latitude))))]];
}


function processKey(connection: NetworkConnection) {
  return (connection.pid ?? 'unknown') + ':' + (connection.processName ?? 'Unknown process');
}

function groupPeers(connections: NetworkConnection[], active: boolean, process: string, search: string): Peer[] {
  const grouped = new Map<string, Peer>();
  const needle = search.trim().toLowerCase();
  for (const connection of connections) {
    if (active && connection.state.toUpperCase() !== 'ESTABLISHED') continue;
    if (process !== 'all' && processKey(connection) !== process) continue;
    const address = maybeHost(connection.remoteAddress);
    if (!address || address === '0.0.0.0' || address === '::') continue;
    if (needle && ![address, connection.processName, connection.pid, connection.localPort, connection.remotePort, connection.protocol, connection.state, connection.scope].join(' ').toLowerCase().includes(needle)) continue;
    if (!grouped.has(address)) grouped.set(address, { address, connections: [] });
    grouped.get(address)!.connections.push(connection);
  }
  return [...grouped.values()].sort((a, b) => b.connections.length - a.connections.length || a.address.localeCompare(b.address));
}

function publicPeer(peer: Peer) {
  if (!peer.connections.length || peer.connections.some(connection => connection.scope !== 'public') || peer.address.includes('%')) return false;
  if (peer.address.includes(':')) {
    const first = Number.parseInt(peer.address.split(':')[0], 16);
    return first >= 0x2000 && first <= 0x3fff && !/^2001:(?:[01]?[0-9a-f]{1,2}:|db8:|:)/.test(peer.address) && !peer.address.startsWith('2002:') && !peer.address.startsWith('3fff:');
  }
  if (!/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(peer.address)) return false;
  const [a, b, c] = peer.address.split('.').map(Number);
  return a > 0 && a < 224 && a !== 10 && a !== 127 && !(a === 100 && b >= 64 && b <= 127) && !(a === 169 && b === 254) && !(a === 172 && b >= 16 && b <= 31) && !(a === 192 && (b === 168 || b === 0 || b === 88 && c === 99)) && !(a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)) && !(a === 203 && b === 0 && c === 113);
}

function parseGeoResponse(value: unknown, addresses: string[]): GeoResult[] {
  if (!record(value) || value.ok !== true || value.provider !== 'ipwho.is' || !Array.isArray(value.results) || value.results.length !== addresses.length || value.results.length > 32) throw new Error('Invalid geography response. No coordinates were accepted.');
  const seen = new Set<string>();
  return value.results.map(item => {
    if (!record(item) || typeof item.ip !== 'string' || !addresses.includes(item.ip) || seen.has(item.ip) || item.source !== 'ipwho.is' || !['located', 'private', 'unavailable'].includes(String(item.status))) throw new Error('Unexpected geography result.');
    seen.add(item.ip);
    for (const key of ['country', 'city', 'asn', 'organization', 'error']) if (item[key] !== null && (typeof item[key] !== 'string' || String(item[key]).length > 500)) throw new Error('Invalid geography metadata.');
    if (typeof item.lookedUpAt !== 'string' || item.lookedUpAt.length > 64 || !Number.isFinite(Date.parse(item.lookedUpAt))) throw new Error('Invalid geography lookup time.');
    if (item.status === 'located') {
      if (typeof item.longitude !== 'number' || !Number.isFinite(item.longitude) || item.longitude < -180 || item.longitude > 180 || typeof item.latitude !== 'number' || !Number.isFinite(item.latitude) || item.latitude < -90 || item.latitude > 90) throw new Error('Invalid geography coordinates.');
    } else if (item.longitude !== null || item.latitude !== null) throw new Error('Unlocated peers must not have coordinates.');
    return { ip: item.ip, status: item.status as GeoResult['status'], longitude: item.longitude as number | null, latitude: item.latitude as number | null, country: item.country as string | null, city: item.city as string | null, asn: item.asn as string | null, organization: item.organization as string | null, source: 'ipwho.is', lookedUpAt: item.lookedUpAt, error: item.error as string | null };
  });
}

function locatedPeers(peers: Peer[], cache: Record<string, GeoResult>, mapped: Set<string>): Endpoint[] {
  return peers.flatMap(peer => {
    const result = cache[peer.address];
    if (mapped.has(peer.address) || !publicPeer(peer) || result?.status !== 'located' || result.longitude === null || result.latitude === null) return [];
    return [{ id: 'geo:' + peer.address, name: [result.city, result.country].filter(Boolean).join(', ') || peer.address, address: peer.address, longitude: result.longitude, latitude: result.latitude, role: 'endpoint' as const, source: 'ipwho.is' as const }];
  });
}

function PeerFacts({ peer }: { peer: Peer }) {
  const unique = (items: (string | number)[]) => [...new Set(items)].join(', ');
  return <dl className="grid gap-2 text-xs"><div><dt className="font-medium">Connections / state</dt><dd className="text-muted-foreground">{peer.connections.length} · {unique(peer.connections.map(connection => connection.state + ' / ' + connection.protocol.toUpperCase()))}</dd></div><div><dt className="font-medium">Process / PID</dt><dd className="break-words text-muted-foreground">{unique(peer.connections.map(connection => (connection.processName || 'Unknown process') + ' / ' + (connection.pid ?? 'unknown')))}</dd></div><div><dt className="font-medium">Remote ports / local ports</dt><dd className="break-words font-mono text-muted-foreground">{unique(peer.connections.map(connection => connection.remotePort ?? 'unknown'))} / {unique(peer.connections.map(connection => connection.localPort))}</dd></div><div><dt className="font-medium">Address family / scope</dt><dd className="text-muted-foreground">{peer.address.includes(':') ? 'IPv6' : /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(peer.address) ? 'IPv4' : 'Host'} · {unique(peer.connections.map(connection => connection.scope))}</dd></div></dl>;
}

// Runnable pure-data regression check; no network, storage, DOM, or WebGL required.
export function atlasSelfCheck() {
  const point = { id: 'one', name: 'Local', address: 'localhost', longitude: 0, latitude: 0, role: 'origin' };
  const assert = (condition: boolean) => { if (!condition) throw new Error('Atlas self-check failed.'); };
  const rejects = (value: unknown) => { try { parseInventory(value); return false; } catch { return true; } };
  const saved = parseInventory([point]);
  assert(saved[0].longitude === 0 && parseInventory(geojson(saved))[0].address === 'localhost');
  assert(host('[::1]') === '::1' && host('EXAMPLE.COM.') === 'example.com');
  assert(rejects([{ ...point, latitude: 91 }]) && rejects([{ ...point, longitude: Infinity }]) && rejects([{ ...point, latitude: '0' }]));
  assert(rejects([{ ...point, address: 'https://example.com' }]) && rejects([{ ...point, address: '256.1.1.1' }]));
  assert(rejects([point, { ...point, id: 'two', address: '127.0.0.1' }]));
  assert(rejects([point, { ...point, id: 'two', role: 'endpoint', address: 'LOCALHOST.' }]));
  assert(rejects({ type: 'FeatureCollection', features: [{ type: 'Feature', properties: point, geometry: { type: 'LineString', coordinates: [[0, 0], [1, 1]] } }] }));
  assert(rejects(Array.from({ length: 501 }, () => point)));
  let oversized = false;
  try { parseImport(' '.repeat(MAX_BYTES + 1)); } catch { oversized = true; }
  assert(oversized && parseImport(JSON.stringify({ version: 1, endpoints: saved })).length === 1);
  const wrap = bounds([{ ...saved[0], longitude: 179 }, { ...saved[0], longitude: -179 }]);
  assert(wrap[1][0] - wrap[0][0] === 2);
  const polar = bounds([{ ...saved[0], latitude: 90 }]);
  assert(polar[0][1] === 85 && polar[1][1] === 85);
  const base: NetworkConnection = { id: 'socket-one', protocol: 'tcp', localAddress: '127.0.0.1', localPort: 1234, remoteAddress: '8.8.8.8', remotePort: 443, state: 'ESTABLISHED', pid: 7, processName: 'test-process', scope: 'public' };
  const sockets = [base, { ...base, id: 'socket-two', remotePort: 80, state: 'TIME_WAIT' }, { ...base, id: 'private', remoteAddress: '10.0.0.1', scope: 'private' as const }, { ...base, id: 'null', remoteAddress: null }];
  const peers = groupPeers(sockets, false, 'all', '');
  assert(peers.length === 2 && peers[0].connections.length === 2);
  assert(groupPeers(sockets, true, 'all', '').find(peer => peer.address === base.remoteAddress)?.connections.length === 1);
  assert(groupPeers(sockets, false, 'all', '443').length === 2 && groupPeers(sockets, false, 'all', 'no-match').length === 0);
  assert(groupPeers(sockets, false, processKey(base), '').length === 2 && groupPeers(sockets, false, 'different-process', '').length === 0);
  assert(publicPeer(peers[0]) && !publicPeer(peers[1]) && !publicPeer({ address: '192.0.2.1', connections: [base] }) && !publicPeer({ address: '2001:db8::1', connections: [base] }));
  const result: GeoResult = { ip: '8.8.8.8', status: 'located', longitude: 0, latitude: 0, city: 'Provider test', country: null, asn: 'AS15169', organization: null, source: 'ipwho.is', lookedUpAt: '2026-11-01T00:00:00.000Z', error: null };
  assert(parseGeoResponse({ ok: true, provider: 'ipwho.is', results: [result] }, [result.ip])[0].longitude === 0);
  let invalidGeo = false;
  try { parseGeoResponse({ ok: true, provider: 'ipwho.is', results: [{ ...result, latitude: 91 }] }, [result.ip]); } catch { invalidGeo = true; }
  assert(invalidGeo);
  const cache = { [result.ip]: result };
  assert(locatedPeers(peers, cache, new Set()).length === 1);
  assert(locatedPeers([], cache, new Set()).length === 0 && locatedPeers(peers, cache, new Set([result.ip])).length === 0);
  assert(locatedPeers(peers, { [result.ip]: { ...result, status: 'unavailable', longitude: null, latitude: null } }, new Set()).length === 0);
  return 'Atlas manual inventory, live grouping, and sourced geography checks passed';
}

const graticule: FeatureCollection<LineString> = { type: 'FeatureCollection', features: [] };
for (let longitude = -180; longitude < 180; longitude += 30) graticule.features.push({ type: 'Feature', properties: {}, geometry: { type: 'LineString', coordinates: Array.from({ length: 35 }, (_, i) => [longitude, -85 + i * 5]) } });
for (let latitude = -75; latitude <= 75; latitude += 15) graticule.features.push({ type: 'Feature', properties: {}, geometry: { type: 'LineString', coordinates: Array.from({ length: 73 }, (_, i) => [-180 + i * 5, latitude]) } });

function GridLayer({ visible }: { visible: boolean }) {
  const { map, isLoaded, resolvedTheme } = useMap();
  useEffect(() => {
    if (!map || !isLoaded || !visible) return;
    map.addSource('atlas-grid', { type: 'geojson', data: graticule });
    map.addLayer({ id: 'atlas-grid-lines', type: 'line', source: 'atlas-grid', paint: { 'line-color': resolvedTheme === 'dark' ? '#94a3b8' : '#475569', 'line-width': 1, 'line-opacity': 0.25 } });
    return () => {
      if (map.getLayer('atlas-grid-lines')) map.removeLayer('atlas-grid-lines');
      if (map.getSource('atlas-grid')) map.removeSource('atlas-grid');
    };
  }, [map, isLoaded, visible, resolvedTheme]);
  return null;
}

function Pin({ point, selected, onSelect }: { point: Endpoint; selected: boolean; onSelect: (id: string) => void }) {
  return <MapMarker longitude={point.longitude} latitude={point.latitude}>
    <MarkerContent><Button variant="ghost" size="icon" type="button" aria-label={'Select ' + point.name} aria-pressed={selected} onClick={() => onSelect(point.id)} className={cn('flex size-9 items-center justify-center rounded-full border-2 border-background shadow-md outline-none focus-visible:ring-4 focus-visible:ring-ring', point.role === 'origin' ? 'bg-amber-500 text-black' : point.source ? 'bg-cyan-600 text-white' : 'bg-primary text-primary-foreground', selected && 'ring-4 ring-primary/40')}><MapPin className="size-4" aria-hidden="true" /></Button></MarkerContent>
    <MarkerTooltip>{point.name} · {point.source ? 'IP geography · ipwho.is' : 'manual ' + point.role}</MarkerTooltip>
  </MapMarker>;
}

type Cluster = { key: string; id: string | null; clusterId: number; count: number; longitude: number; latitude: number };
function OfflineClusters({ points, selectedId, onSelect }: { points: Endpoint[]; selectedId: string | null; onSelect: (id: string) => void }) {
  const { map, isLoaded } = useMap();
  const [visible, setVisible] = useState<Cluster[]>([]);
  const data = useMemo(() => geojson(points), [points]);
  // ponytail: capped at 500 manual + 128 visit-located points; HTML counts stay offline. Bundle glyphs before using MapClusterLayer's text layer.
  useEffect(() => {
    if (!map || !isLoaded) return;
    let previous = '';
    map.addSource('atlas-clusters', { type: 'geojson', data, cluster: true, clusterRadius: 50, clusterMaxZoom: 14 });
    map.addLayer({ id: 'atlas-cluster-query', type: 'circle', source: 'atlas-clusters', paint: { 'circle-radius': 1, 'circle-opacity': 0 } });
    const sync = () => {
      if (!map.getSource('atlas-clusters') || !map.isSourceLoaded('atlas-clusters')) return;
      const found = new Map<string, Cluster>();
      for (const feature of map.querySourceFeatures('atlas-clusters')) {
        if (feature.geometry.type !== 'Point') continue;
        const properties = feature.properties ?? {};
        const clustered = Boolean(properties.cluster);
        const key = (clustered ? 'cluster-' : 'point-') + (clustered ? properties.cluster_id : properties.id);
        const pointId = clustered ? null : String(properties.id);
        const [longitude, latitude] = feature.geometry.coordinates;
        found.set(key, { key, id: pointId, clusterId: Number(properties.cluster_id), count: Number(properties.point_count ?? 1), longitude, latitude });
      }
      const next = [...found.values()].sort((a, b) => a.key.localeCompare(b.key));
      const signature = JSON.stringify(next);
      if (signature !== previous) { previous = signature; setVisible(next); }
    };
    map.on('render', sync);
    return () => {
      map.off('render', sync);
      if (map.getLayer('atlas-cluster-query')) map.removeLayer('atlas-cluster-query');
      if (map.getSource('atlas-clusters')) map.removeSource('atlas-clusters');
    };
  }, [map, isLoaded, data]);
  async function expand(cluster: Cluster) {
    try {
      const source = map?.getSource('atlas-clusters') as GeoJSONSource | undefined;
      if (!source || !map) return;
      const zoom = await source.getClusterExpansionZoom(cluster.clusterId);
      if (map.getSource('atlas-clusters') === source) map.easeTo({ center: [cluster.longitude, cluster.latitude], zoom, duration: 0 });
    } catch { toast.error('Cluster changed. Please select it again.'); }
  }
  return <>{visible.map(cluster => {
    if (cluster.id !== null) {
      const point = points.find(item => item.id === cluster.id);
      return point ? <Pin key={cluster.key} point={point} selected={selectedId === point.id} onSelect={onSelect} /> : null;
    }
    return <MapMarker key={cluster.key} longitude={cluster.longitude} latitude={cluster.latitude}><MarkerContent><Button variant="default" size="icon" type="button" onClick={() => void expand(cluster)} aria-label={'Zoom into cluster of ' + cluster.count + ' saved locations'} className="flex size-11 items-center justify-center rounded-full border-2 border-background bg-primary text-sm font-bold text-primary-foreground shadow-md focus-visible:ring-4 focus-visible:ring-ring">{cluster.count}</Button></MarkerContent><MarkerTooltip>{cluster.count} saved locations · click to expand</MarkerTooltip></MapMarker>;
  })}</>;
}

function MapEvents({ onReady, onProblem, onLost }: { onReady: (ready: boolean) => void; onProblem: () => void; onLost: () => void }) {
  const { map, isLoaded } = useMap();
  useEffect(() => { onReady(isLoaded); return () => onReady(false); }, [isLoaded, onReady]);
  useEffect(() => {
    if (!map) return;
    const canvas = map.getCanvas();
    map.on('error', onProblem);
    canvas.addEventListener('webglcontextlost', onLost);
    return () => { map.off('error', onProblem); canvas.removeEventListener('webglcontextlost', onLost); };
  }, [map, onProblem, onLost]);
  return null;
}

class MapBoundary extends Component<{ children: ReactNode; fallback: ReactNode; onFailure: () => void }, { failed: boolean }> {
  state = { failed: false };
  static getDerivedStateFromError() { return { failed: true }; }
  componentDidCatch() { this.props.onFailure(); }
  render() { return this.state.failed ? this.props.fallback : this.props.children; }
}

function Pager({ page, count, onPage }: { page: number; count: number; onPage: (page: number) => void }) {
  const pages = Math.max(1, Math.ceil(count / PAGE_SIZE));
  return <div className="flex items-center justify-between gap-3 pt-3 text-xs text-muted-foreground"><span>{count} total · page {page + 1} of {pages}</span><div className="flex gap-2"><Button variant="outline" size="sm" disabled={page === 0} onClick={() => onPage(page - 1)}>Previous</Button><Button variant="outline" size="sm" disabled={page + 1 >= pages} onClick={() => onPage(page + 1)}>Next</Button></div></div>;
}

export function Atlas({ network, live = true, onDiagnose }: { network: NetworkSnapshot | null; live?: boolean; onDiagnose?: (target: string, kind?: string) => void }) {
  const [stored, setStored] = useStorage<unknown>('portscope.atlas.v1', []);
  const inventory = useMemo(() => {
    try { return { points: parseInventory(stored), error: '' }; }
    catch (error) { return { points: [] as Endpoint[], error: error instanceof Error ? error.message : 'Invalid saved inventory.' }; }
  }, [stored]);
  const points = inventory.points;
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedAddress, setSelectedAddress] = useState<string | null>(null);
  const [geoEnabled, setGeoEnabled] = useState(false);
  const [geoConsentOpen, setGeoConsentOpen] = useState(false);
  const [geoCache, setGeoCache] = useState<Record<string, GeoResult>>({});
  const [geoBusy, setGeoBusy] = useState(false);
  const [geoError, setGeoError] = useState('');
  const [geoStopped, setGeoStopped] = useState(false);
  const [geoUsed, setGeoUsed] = useState(0);
  const geoAttempted = useRef(new Set<string>());
  const geoAbort = useRef<AbortController | null>(null);
  const geoGate = useRef(false);
  geoGate.current = live && geoEnabled && !geoStopped;
  const [activeOnly, setActiveOnly] = useState(false);
  const [processFilter, setProcessFilter] = useState('all');
  const [online, setOnline] = useState(false);
  const [consentOpen, setConsentOpen] = useState(false);
  const [globe, setGlobe] = useState(false);
  const [grid, setGrid] = useState(true);
  const [links, setLinks] = useState(false);
  const [clusters, setClusters] = useState(false);
  const [mapReady, setMapReady] = useState(false);
  const [mapFailed, setMapFailed] = useState(false);
  const [mapProblem, setMapProblem] = useState(false);
  const [attempt, setAttempt] = useState(0);
  const mapRef = useRef<MapRef>(null);
  const viewport = useRef(initialViewport);
  const [draft, setDraft] = useState<Draft | null>(null);
  const [formError, setFormError] = useState('');
  const [deleting, setDeleting] = useState<Endpoint | 'reset' | null>(null);
  const [importOpen, setImportOpen] = useState(false);
  const [importing, setImporting] = useState<Endpoint[] | null>(null);
  const [importError, setImportError] = useState('');
  const [importBusy, setImportBusy] = useState(false);
  const importSequence = useRef(0);
  const [format, setFormat] = useState('json');
  const [filter, setFilter] = useState('');
  const [page, setPage] = useState(0);
  const [peerFilter, setPeerFilter] = useState('');
  const [peerPage, setPeerPage] = useState(0);
  const origin = points.find(point => point.role === 'origin');
  const connections = network?.connections ?? [];
  const mapped = useMemo(() => new Set(points.map(point => point.address)), [points]);
  const connectionsByAddress = useMemo(() => {
    const grouped = new Map<string, NetworkConnection[]>();
    for (const connection of connections) for (const address of new Set([maybeHost(connection.localAddress), maybeHost(connection.remoteAddress)])) {
      if (address) grouped.set(address, [...(grouped.get(address) ?? []), connection]);
    }
    return grouped;
  }, [connections]);
  const addresses = useMemo(() => [...new Set([...connections.flatMap(connection => [maybeHost(connection.localAddress), maybeHost(connection.remoteAddress)]), ...(network?.interfaces ?? []).map(item => maybeHost(item.address))])].filter((address): address is string => Boolean(address) && address !== '0.0.0.0' && address !== '::').sort(), [connections, network?.interfaces]);
  const processOptions = useMemo(() => [...new Map(connections.map(connection => [processKey(connection), (connection.processName || 'Unknown process') + ' · PID ' + (connection.pid ?? 'unknown')])).entries()].sort((a, b) => a[1].localeCompare(b[1])), [connections]);
  const allPeers = useMemo(() => groupPeers(connections, false, 'all', ''), [connections]);
  const peers = useMemo(() => groupPeers(connections, activeOnly, processFilter, peerFilter), [connections, activeOnly, processFilter, peerFilter]);
  const publicAddresses = useMemo(() => peers.filter(peer => publicPeer(peer) && !mapped.has(peer.address)).map(peer => peer.address).sort(), [peers, mapped]);
  const publicKey = JSON.stringify(publicAddresses);
  const latestPublic = useRef(publicAddresses);
  latestPublic.current = publicAddresses;
  const [geoTick, setGeoTick] = useState(0);
  const requestGeo = geoEnabled && live && !geoStopped;
  useEffect(() => () => { geoAbort.current?.abort(); geoAbort.current = null; setGeoBusy(false); }, [requestGeo]);
  useEffect(() => {
    if (!requestGeo || geoAbort.current || geoAttempted.current.size >= MAX_LOOKUPS) return;
    if (!publicAddresses.some(address => !geoAttempted.current.has(address))) return;
    // Defer one turn so React StrictMode's probe cleanup cannot consume the visit budget.
    const timer = window.setTimeout(async () => {
      if (!geoGate.current || geoAbort.current) return;
      const batch = latestPublic.current.filter(address => !geoAttempted.current.has(address)).slice(0, Math.min(GEO_BATCH, MAX_LOOKUPS - geoAttempted.current.size));
      if (!batch.length) return;
      const controller = new AbortController();
      geoAbort.current = controller;
      for (const address of batch) geoAttempted.current.add(address);
      setGeoUsed(geoAttempted.current.size); setGeoBusy(true);
      const timeout = window.setTimeout(() => controller.abort(), 20000);
      try {
        const response = await fetch('/api/geo', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ addresses: batch, consent: true }), signal: controller.signal, cache: 'no-store' });
        if (!response.ok) throw new Error('Geography lookup HTTP ' + response.status + '. Automatic lookups stopped for this visit.');
        const results = parseGeoResponse(await response.json(), batch);
        if (!geoGate.current || controller.signal.aborted) return;
        setGeoCache(previous => Object.fromEntries([...Object.entries(previous), ...results.map(result => [result.ip, result] as const)]));
      } catch (error) {
        if (controller.signal.aborted && geoAbort.current !== controller) return;
        if (!geoGate.current) return;
        const message = error instanceof Error ? error.message : 'Geography lookup unavailable.';
        const lookedUpAt = new Date().toISOString();
        setGeoCache(previous => ({ ...previous, ...Object.fromEntries(batch.map(ip => [ip, { ip, status: 'unavailable', longitude: null, latitude: null, country: null, city: null, asn: null, organization: null, source: 'ipwho.is', lookedUpAt, error: message } as GeoResult])) }));
        setGeoError(message); setGeoStopped(true);
      } finally {
        window.clearTimeout(timeout);
        if (geoAbort.current === controller) { geoAbort.current = null; setGeoBusy(false); setGeoTick(value => value + 1); }
      }
    }, geoAttempted.current.size ? 11000 : 350);
    return () => window.clearTimeout(timer);
  }, [requestGeo, publicKey, geoTick]);
  function revokeGeo() {
    geoGate.current = false; geoAbort.current?.abort(); setGeoEnabled(false); setGeoBusy(false);
  }
  const autoPoints = useMemo(() => geoEnabled ? locatedPeers(peers, geoCache, mapped) : [], [geoEnabled, peers, geoCache, mapped]);
  const plotted = useMemo(() => [...points, ...autoPoints], [points, autoPoints]);
  const selected = plotted.find(point => point.id === selectedId);
  const selectedPeer = peers.find(peer => peer.address === (selected?.address ?? selectedAddress));
  const selectedGeo = selectedPeer ? geoCache[selectedPeer.address] : undefined;
  const basemapActive = online && live;
  const filtered = points.filter(point => [point.name, point.address, point.role].join(' ').toLowerCase().includes(filter.toLowerCase()));
  const currentPage = Math.min(page, Math.max(0, Math.ceil(filtered.length / PAGE_SIZE) - 1));
  const currentPeerPage = Math.min(peerPage, Math.max(0, Math.ceil(peers.length / PAGE_SIZE) - 1));
  const arcs = useMemo(() => origin ? plotted.filter(point => point.role === 'endpoint').map(point => ({ id: point.id, from: [origin.longitude, origin.latitude] as [number, number], to: [point.longitude, point.latitude] as [number, number] })) : [], [origin, plotted]);
  const onProblem = useCallback(() => setMapProblem(true), []);
  const onLost = useCallback(() => { setMapReady(false); setMapFailed(true); }, []);
  const selectPoint = useCallback((id: string) => { setSelectedId(id); setSelectedAddress(null); }, []);
  const currentStates = (address: string) => [...new Set((connectionsByAddress.get(address) ?? []).map(connection => connection.state))].join(', ') || (network ? 'Not observed in snapshot' : 'Snapshot unavailable');
  function selectPeer(peer: Peer) {
    const point = plotted.find(point => point.address === peer.address);
    setSelectedAddress(peer.address); setSelectedId(point?.id ?? null);
    if (point) focus(point);
  }
  function geoStatus(peer: Peer) {
    if (mapped.has(peer.address)) return 'Manual coordinates';
    if (!publicPeer(peer)) return 'Private / reserved / unknown — not located';
    const result = geoCache[peer.address];
    if (result?.status === 'located') return [result.city, result.country].filter(Boolean).join(', ') || 'Located';
    if (result?.status === 'private') return 'Provider classified private — not located';
    if (result?.status === 'unavailable') return 'Unavailable — no coordinates';
    if (geoAttempted.current.has(peer.address)) return geoBusy ? 'Lookup in progress / attempted' : 'Not resolved — no automatic retry';
    if (!geoEnabled) return 'Public — consent required';
    if (!live) return 'Paused — not located';
    if (geoUsed >= MAX_LOOKUPS) return 'Visit limit reached — not located';
    return geoStopped ? 'Lookups stopped — not located' : 'Queued — not located';
  }

  function openForm(point?: Endpoint, address = '', role: Endpoint['role'] = 'endpoint') {
    setFormError('');
    setDraft(point ? { ...point, longitude: String(point.longitude), latitude: String(point.latitude) } : { id: crypto.randomUUID(), name: '', address, longitude: '', latitude: '', role });
  }
  function save() {
    if (!draft || inventory.error) return;
    try {
      if (!draft.longitude.trim() || !draft.latitude.trim()) throw new Error('Enter both coordinates explicitly; nothing is inferred from an address.');
      const point = { ...draft, longitude: Number(draft.longitude), latitude: Number(draft.latitude) };
      const exists = points.some(item => item.id === draft.id);
      const next = parseInventory(exists ? points.map(item => item.id === draft.id ? point : item) : [...points, point]);
      setStored(next); setSelectedId(draft.id); setDraft(null); toast.success('Atlas updated in this browser.');
    } catch (error) { setFormError(error instanceof Error ? error.message : 'Could not save endpoint.'); }
  }
  function fit() {
    if (!mapRef.current || plotted.length === 0) return;
    mapRef.current.fitBounds(bounds(plotted), { padding: 70, maxZoom: 9, duration: 0 });
  }
  function focus(point: Endpoint) {
    setSelectedId(point.id); setSelectedAddress(null);
    if (mapReady) mapRef.current?.flyTo({ center: [point.longitude, globe ? point.latitude : Math.max(-85, Math.min(85, point.latitude))], zoom: Math.max(mapRef.current.getZoom(), 4), duration: 0 });
  }
  async function loadFile(file?: File) {
    const sequence = ++importSequence.current;
    setImporting(null); setImportError(''); setImportBusy(false);
    if (!file) return;
    try {
      if (file.size > MAX_BYTES) throw new Error('Import is limited to 1 MiB.');
      setImportBusy(true);
      const parsed = parseImport(await file.text());
      if (sequence !== importSequence.current) return;
      if (!parsed.length) throw new Error('The file contains no endpoints.');
      setImporting(parsed);
    } catch (error) { if (sequence === importSequence.current) setImportError(error instanceof Error ? error.message : 'Cannot read this file.'); }
    finally { if (sequence === importSequence.current) setImportBusy(false); }
  }
  function appendImport() {
    if (!importing || inventory.error) return;
    try {
      const incoming = importing.map(point => ({ ...point, id: crypto.randomUUID() }));
      const next = parseInventory([...points, ...incoming]);
      setStored(next); setImportOpen(false); setImporting(null); toast.success(incoming.length + ' locations imported.');
    } catch (error) { setImportError(error instanceof Error ? error.message : 'Import rejected. Existing inventory was not changed.'); }
  }
  function exportInventory() {
    try { download('portscope-atlas.' + (format === 'geojson' ? 'geojson' : 'json'), JSON.stringify(format === 'geojson' ? geojson(points) : { version: 1, kind: 'manual-inventory', endpoints: points }, null, 2), format === 'geojson' ? 'application/geo+json' : 'application/json'); }
    catch { toast.error('Export failed. Your saved inventory was not changed.'); }
  }
  const fallback = <div className="flex h-full min-h-96 items-center justify-center p-8"><div className="max-w-md space-y-4 text-center"><Globe2 className="mx-auto size-10 text-muted-foreground" /><h3 className="font-semibold">Map renderer unavailable</h3><p className="text-sm text-muted-foreground">WebGL2 may be disabled or its context was lost. Your saved inventory, connection states, editing, and exports remain available in the table below.</p><Button variant="outline" onClick={() => { setMapFailed(false); setMapProblem(false); setAttempt(value => value + 1); }}>Retry map</Button></div></div>;

  return <TooltipProvider><div className="space-y-6" data-testid="network-atlas">
    <div className="flex flex-wrap items-start justify-between gap-4"><div className="space-y-2"><div className="flex items-center gap-2 text-xs font-medium uppercase tracking-widest text-muted-foreground"><Compass className="size-4" /> Network atlas</div><h2 className="text-2xl font-semibold tracking-tight">Live connections. Known locations.</h2><p className="max-w-2xl text-sm text-muted-foreground">Actual remote peers from your latest network sample, alongside your manual inventory. Optional public-IP geography requires separate consent; private and unknown endpoints stay unlocated.</p></div><Badge variant="outline" className="gap-1.5"><ShieldCheck className="size-3.5" /> {online && geoEnabled ? 'Basemap + IP geography consent' : online ? 'Online basemap · consent granted' : geoEnabled ? 'IP geography · consent granted' : 'Offline · no external requests'}</Badge></div>

    {inventory.error && <Alert variant="destructive"><AlertTitle>Saved inventory needs attention</AlertTitle><AlertDescription><p>{inventory.error} The stored data has not been overwritten. Download a recovery copy before resetting.</p><div className="mt-2 flex flex-wrap gap-2"><Button variant="outline" size="sm" onClick={() => download('portscope-atlas-recovery.json', JSON.stringify(stored, null, 2))}>Download recovery JSON</Button><Button variant="destructive" size="sm" onClick={() => setDeleting('reset')}>Reset invalid inventory</Button></div></AlertDescription></Alert>}

    <Card className="gap-0 overflow-hidden py-0"><div className="flex flex-wrap items-center justify-between gap-3 border-b p-4"><div className="flex flex-wrap items-center gap-2"><Badge variant="secondary">{points.length} saved · {autoPoints.length} live located</Badge><Badge variant="outline">{origin ? '1 origin' : 'No origin set'}</Badge><Button variant="outline" size="sm" onClick={fit} disabled={!mapReady || !plotted.length}><LocateFixed /> Fit inventory</Button><Button variant="ghost" size="sm" disabled={!mapReady} onClick={() => mapRef.current?.jumpTo(initialViewport)}><Globe2 /> World view</Button></div><Button size="sm" disabled={Boolean(inventory.error) || points.length >= MAX_POINTS} onClick={() => openForm()}><Plus /> Add endpoint</Button></div>
      <div className="relative h-[430px] bg-muted/30 sm:h-[500px]" aria-label="Map of manual locations and consented public-IP geography; equivalent peer and inventory tables follow">
        {mapFailed ? fallback : <MapBoundary key={attempt} fallback={fallback} onFailure={onLost}><MapCanvas key={String(basemapActive) + '-' + String(globe)} ref={mapRef} blank={!basemapActive} styles={basemapActive ? CARTO : undefined} projection={{ type: globe ? 'globe' : 'mercator' }} center={viewport.current.center} zoom={viewport.current.zoom} bearing={viewport.current.bearing} pitch={viewport.current.pitch} onViewportChange={value => { viewport.current = value; }} attributionControl={{ compact: false }} renderWorldCopies={!globe}>
          <MapEvents onReady={setMapReady} onProblem={onProblem} onLost={onLost} />
          {!basemapActive && <MapGeoJSON data={localWorld as FeatureCollection} fillPaint={{ 'fill-color': '#64748b', 'fill-opacity': 0.12 }} linePaint={{ 'line-color': '#64748b', 'line-width': 0.7, 'line-opacity': 0.4 }} />}<GridLayer visible={grid} />
          {links && arcs.length > 0 && <MapArc data={arcs} curvature={0} paint={{ 'line-color': '#f59e0b', 'line-width': 2, 'line-opacity': 0.7, 'line-dasharray': [3, 3] }} onClick={event => selectPoint(String(event.arc.id))} />}
          {clusters && plotted.length > 1 ? <OfflineClusters points={plotted} selectedId={selectedId} onSelect={selectPoint} /> : plotted.map(point => <Pin key={point.id} point={point} selected={selectedId === point.id} onSelect={selectPoint} />)}
          {selected && <MapPopup key={selected.id} longitude={selected.longitude} latitude={selected.latitude} closeButton closeOnClick={false} onClose={() => setSelectedId(null)}><div className="max-h-80 space-y-3 overflow-y-auto pr-4"><p className="font-semibold">{selected.name}</p><p className="break-all font-mono text-xs">{selected.address}</p><Badge variant="outline">{selected.source ? 'Approximate IP geography · ipwho.is' : 'Manual ' + selected.role}</Badge><p className="text-xs text-muted-foreground">{selected.longitude}, {selected.latitude}<br />{currentStates(selected.address)}</p>{selectedPeer && <PeerFacts peer={selectedPeer} />}{selected.source && selectedGeo && <p className="text-xs text-muted-foreground">{selectedGeo.organization || selectedGeo.asn || 'Provider metadata unavailable'}<br />Looked up {new Date(selectedGeo.lookedUpAt).toLocaleString()}</p>}<div className="flex flex-wrap gap-2">{!selected.source && <Button variant="outline" size="sm" onClick={() => openForm(selected)}><Pencil /> Edit location</Button>}{onDiagnose && <><Button variant="outline" size="sm" onClick={() => onDiagnose(selected.address, 'ping')}>Ping</Button><Button variant="outline" size="sm" onClick={() => onDiagnose(selected.address, 'mtr')}>MTR</Button></>}</div></div></MapPopup>}
          <MapControls showZoom showCompass showLocate={false} showFullscreen={typeof document !== 'undefined' && document.fullscreenEnabled} />
        </MapCanvas></MapBoundary>}
        {!plotted.length && !mapFailed && <div className="pointer-events-none absolute inset-0 flex items-center justify-center p-8"><div className="max-w-sm rounded-xl border bg-background/90 p-5 text-center shadow-sm"><MapPin className="mx-auto mb-3 size-7 text-muted-foreground" /><p className="font-medium">No locations invented.</p><p className="mt-2 text-sm text-muted-foreground">Peers stay unlocated until you add known coordinates or consent to public-IP geography. Land outlines are bundled locally.</p></div></div>}
        <div className="pointer-events-none absolute left-3 top-3 rounded-md border bg-background/90 px-2.5 py-1.5 text-xs font-medium">{globe ? 'Globe' : '2D Mercator'} · {basemapActive ? 'CARTO basemap' : online ? 'Basemap paused · local land + grid' : 'Local land + grid'}</div>
      </div>
      <div className="flex flex-wrap items-center gap-x-6 gap-y-4 border-t p-4"><div className="flex items-center gap-2"><Switch id="atlas-grid" checked={grid} onCheckedChange={setGrid} /><Label htmlFor="atlas-grid">Coordinate grid</Label></div><div className="flex items-center gap-2"><Switch id="atlas-globe" checked={globe} onCheckedChange={setGlobe} /><Label htmlFor="atlas-globe">Globe</Label></div><div className="flex items-center gap-2"><Switch id="atlas-cluster" checked={clusters} onCheckedChange={setClusters} disabled={plotted.length < 2} /><Label htmlFor="atlas-cluster">Cluster points</Label></div><div className="flex items-center gap-2"><Switch id="atlas-links" checked={links} onCheckedChange={setLinks} disabled={!arcs.length} /><Label htmlFor="atlas-links">Reference links</Label></div><Separator orientation="vertical" className="hidden h-5 md:block" /><div className="flex items-center gap-2"><Switch id="atlas-online" checked={online} onCheckedChange={checked => { if (checked) setConsentOpen(true); else { setOnline(false); setMapProblem(false); } }} /><Label htmlFor="atlas-online">Online basemap</Label></div></div>
      <p className="px-4 pb-4 text-xs text-muted-foreground">Gold = manual origin · accent = manual endpoint · cyan = approximate public-IP geography. Links connect displayed coordinates; they are not observed routes, traceroutes, or evidence of traffic. Private and loopback addresses have no inferable location. Offline outlines: Natural Earth, public domain.</p>
      {online && <p className="border-t px-4 py-3 text-xs text-muted-foreground">Online requests reveal your IP and viewed area to CARTO and its map providers. © <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noreferrer" className="underline">OpenStreetMap contributors</a> · © <a href="https://carto.com/attributions" target="_blank" rel="noreferrer" className="underline">CARTO</a>. Consent lasts only while this atlas view stays mounted. Global Live off pauses the online basemap.</p>}
    </Card>
    {mapProblem && <Alert><AlertTitle>Some map resources could not be rendered</AlertTitle><AlertDescription><p>The accessible inventory is unaffected.{online ? ' The basemap may be unreachable; return offline to use only local data.' : ' Try the map again or use the inventory table.'}</p>{online && <Button variant="outline" size="sm" onClick={() => { setOnline(false); setMapProblem(false); }}>Return offline</Button>}</AlertDescription></Alert>}

    <Card><CardHeader className="gap-3"><div className="flex flex-wrap items-center justify-between gap-3"><div><CardTitle>Location inventory</CardTitle><CardDescription className="mt-2">Always available without WebGL. Matching is by exact normalized host/IP, never DNS resolution.</CardDescription></div><div className="flex flex-wrap gap-2"><Button variant="outline" size="sm" disabled={Boolean(inventory.error)} onClick={() => { setImportOpen(true); setImporting(null); setImportError(''); }}><Upload /> Import</Button><Select value={format} onValueChange={setFormat}><SelectTrigger aria-label="Export format" size="sm"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="json">JSON</SelectItem><SelectItem value="geojson">GeoJSON</SelectItem></SelectContent></Select><Button variant="outline" size="sm" disabled={!points.length} onClick={exportInventory}><Download /> Export</Button></div></div><Label htmlFor="atlas-search" className="sr-only">Filter saved locations</Label><Input id="atlas-search" placeholder="Filter saved names, addresses, or roles…" value={filter} onChange={event => { setFilter(event.target.value); setPage(0); }} /></CardHeader><CardContent>
      <Table><TableCaption>Manually provided coordinates; state reflects the latest supplied network snapshot, not reachability.</TableCaption><TableHeader><TableRow><TableHead>Name / address</TableHead><TableHead>Role</TableHead><TableHead>Longitude / latitude</TableHead><TableHead>Current connection state</TableHead><TableHead className="text-right">Actions</TableHead></TableRow></TableHeader><TableBody>{filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE).map(point => <TableRow key={point.id} data-state={selectedId === point.id ? 'selected' : undefined}><TableCell><Button variant="link" type="button" className="h-auto justify-start whitespace-normal p-0 text-left font-medium text-foreground" onClick={() => focus(point)} aria-label={'Select saved location ' + point.name}>{point.name}</Button><div className="mt-1 max-w-64 break-all font-mono text-xs text-muted-foreground">{point.address}</div></TableCell><TableCell><Badge variant={point.role === 'origin' ? 'secondary' : 'outline'}>{point.role}</Badge></TableCell><TableCell className="font-mono text-xs">{point.longitude}, {point.latitude}</TableCell><TableCell className="max-w-64 whitespace-normal text-xs">{currentStates(point.address)}{(connectionsByAddress.get(point.address)?.length ?? 0) > 0 && <p className="mt-1 text-muted-foreground">{connectionsByAddress.get(point.address)!.length} observed connections</p>}</TableCell><TableCell><div className="flex justify-end gap-1"><Tooltip><TooltipTrigger asChild><Button variant="ghost" size="icon-sm" aria-label={'Copy address for ' + point.name} onClick={() => void copyText(point.address).then(() => toast.success('Address copied.')).catch(() => toast.error('Clipboard unavailable. Select the address in the table.'))}><Copy /></Button></TooltipTrigger><TooltipContent>Copy address</TooltipContent></Tooltip><Button variant="ghost" size="icon-sm" aria-label={'Edit ' + point.name} onClick={() => openForm(point)}><Pencil /></Button><Button variant="ghost" size="icon-sm" aria-label={'Delete ' + point.name} onClick={() => setDeleting(point)}><Trash2 /></Button></div></TableCell></TableRow>)}{!filtered.length && <TableRow><TableCell colSpan={5} className="h-24 text-center text-muted-foreground">{points.length ? 'No matching saved locations.' : 'No saved locations. Add or import known coordinates; none are inferred.'}</TableCell></TableRow>}</TableBody></Table><Pager page={currentPage} count={filtered.length} onPage={setPage} />
    </CardContent></Card>

    <Card data-testid="atlas-live-peers"><CardHeader className="gap-4"><div className="flex flex-wrap items-center justify-between gap-3"><div><CardTitle>Live destination peers <Badge variant="secondary" className="ml-2">{peers.length}</Badge></CardTitle><CardDescription className="mt-2">Real sampled remote endpoints, grouped by host/IP. Filters apply to live points and optional lookups; saved manual locations remain.</CardDescription></div><Badge variant={live ? 'secondary' : 'outline'}>{live ? 'Following network stream' : 'Paused · last sample retained'}</Badge></div>
      <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground"><span>{network?.scannedAt ? 'Sampled at ' + new Date(network.scannedAt).toLocaleString() : 'No network sample yet'}</span><span>{allPeers.length} unfiltered peers · {peers.reduce((total, peer) => total + peer.connections.length, 0)} matching connections</span><span>{autoPoints.length} provider-located · {peers.filter(peer => !mapped.has(peer.address) && !autoPoints.some(point => point.address === peer.address)).length} unlocated</span></div>
      <div className="grid gap-3 md:grid-cols-[1fr_1fr_auto]"><div className="space-y-2"><Label htmlFor="atlas-peer-search">Search live peers</Label><Input id="atlas-peer-search" value={peerFilter} onChange={event => { setPeerFilter(event.target.value); setPeerPage(0); }} placeholder="IP, port, process, PID, scope, state…" /></div><div className="space-y-2"><Label htmlFor="atlas-process-filter">Process</Label><Select value={processFilter} onValueChange={value => { setProcessFilter(value); setPeerPage(0); }}><SelectTrigger id="atlas-process-filter" className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="all">All processes</SelectItem>{processFilter !== 'all' && !processOptions.some(([key]) => key === processFilter) && <SelectItem value={processFilter}>Selected process · not in sample</SelectItem>}{processOptions.map(([key, label]) => <SelectItem key={key} value={key}>{label}</SelectItem>)}</SelectContent></Select></div><div className="flex items-center gap-2 md:pt-7"><Switch id="atlas-active-only" checked={activeOnly} onCheckedChange={checked => { setActiveOnly(checked); setPeerPage(0); }} /><Label htmlFor="atlas-active-only">ESTABLISHED only</Label></div></div>
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border bg-muted/20 p-3"><div className="space-y-1"><div className="flex items-center gap-2"><Switch id="atlas-geography" checked={geoEnabled} onCheckedChange={checked => { if (checked) setGeoConsentOpen(true); else revokeGeo(); }} /><Label htmlFor="atlas-geography">Public-IP geography</Label><Badge variant="outline">Opt-in · ipwho.is</Badge></div><p className="text-xs text-muted-foreground">{geoEnabled ? geoBusy ? 'Resolving a small batch through the local server…' : !live ? 'Lookups paused with global Live off.' : geoStopped ? 'Automatic lookups stopped after an error.' : geoUsed >= MAX_LOOKUPS ? 'Visit limit reached; no further IPs are sent.' : 'New matching public peers are looked up progressively.' : 'Off. Public IPs are not sent to a geography provider.'} {geoUsed}/{MAX_LOOKUPS} distinct IP attempts this visit.</p></div>{geoBusy && <Badge variant="secondary" role="status">Looking up</Badge>}</div>
      <p className="text-xs text-muted-foreground">IP geography is approximate provider data, not device geolocation or a measured network route. Private, reserved, loopback, and unknown destinations stay unlocated unless you supply coordinates.</p>
    </CardHeader><CardContent>
      {network?.limited && <Alert><AlertTitle>Partial connection inventory</AlertTitle><AlertDescription>Showing {network.connections.length} of {network.totalObserved} observed sockets. Established and active connections are prioritized over listeners and TIME_WAIT; some sockets are omitted.</AlertDescription></Alert>}
      {network?.error && <Alert className="mb-4"><AlertTitle>Network sample warning</AlertTitle><AlertDescription>{network.error}</AlertDescription></Alert>}
      {geoError && <Alert className="mb-4"><AlertTitle>Geography lookups stopped</AlertTitle><AlertDescription>{geoError} No automatic retries. Manual inventory and connection inspection remain available.</AlertDescription></Alert>}
      <Table><TableCaption>Membership and state follow the latest supplied sample, not a reachability test. No traffic volume or physical route is inferred. Ports are observed socket ports.</TableCaption><TableHeader><TableRow><TableHead>Remote endpoint / count</TableHead><TableHead>Family / scope</TableHead><TableHead>Remote / local ports</TableHead><TableHead>State / process / PID</TableHead><TableHead>Geography / source</TableHead><TableHead className="text-right">Actions</TableHead></TableRow></TableHeader><TableBody>{peers.slice(currentPeerPage * PAGE_SIZE, (currentPeerPage + 1) * PAGE_SIZE).map(peer => {
        const result = geoCache[peer.address];
        const point = points.find(item => item.address === peer.address);
        return <TableRow key={peer.address} data-state={selectedPeer?.address === peer.address ? 'selected' : undefined}>
          <TableCell><Button variant="link" className="h-auto max-w-64 justify-start whitespace-normal break-all p-0 text-left font-mono text-xs text-foreground" aria-label={'Inspect peer ' + peer.address} onClick={() => selectPeer(peer)}>{peer.address}</Button><p className="mt-1 text-xs text-muted-foreground">{peer.connections.length} connections</p></TableCell>
          <TableCell className="text-xs">{peer.address.includes(':') ? 'IPv6' : /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(peer.address) ? 'IPv4' : 'Host'}<p className="mt-1 text-muted-foreground">{[...new Set(peer.connections.map(connection => connection.scope))].join(', ')}</p></TableCell>
          <TableCell className="max-w-40 whitespace-normal font-mono text-xs">{[...new Set(peer.connections.map(connection => connection.remotePort ?? '—'))].join(', ')}<p className="mt-1 text-muted-foreground">Local: {[...new Set(peer.connections.map(connection => connection.localPort))].join(', ')}</p></TableCell>
          <TableCell className="max-w-64 whitespace-normal text-xs">{[...new Set(peer.connections.map(connection => connection.state + ' / ' + connection.protocol.toUpperCase()))].join(', ')}<p className="mt-1 text-muted-foreground">{[...new Set(peer.connections.map(connection => (connection.processName || 'Unknown process') + ' / ' + (connection.pid ?? 'unknown PID')))].join(', ')}</p></TableCell>
          <TableCell className="max-w-64 whitespace-normal text-xs">{geoStatus(peer)}{point && <p className="mt-1 text-muted-foreground">User supplied · {point.longitude}, {point.latitude}</p>}{!point && result && <p className="mt-1 text-muted-foreground">ipwho.is · {new Date(result.lookedUpAt).toLocaleTimeString()}{result.organization ? ' · ' + result.organization : ''}</p>}{!point && result?.error && <p className="mt-1 text-muted-foreground">{result.error}</p>}</TableCell>
          <TableCell><div className="flex flex-wrap justify-end gap-1"><Button variant="outline" size="sm" onClick={() => selectPeer(peer)}>Inspect</Button>{onDiagnose && <><Button variant="outline" size="sm" aria-label={'Ping ' + peer.address} onClick={() => onDiagnose(peer.address, 'ping')}>Ping</Button><Button variant="outline" size="sm" aria-label={'MTR ' + peer.address} onClick={() => onDiagnose(peer.address, 'mtr')}>MTR</Button></>}<Button variant="ghost" size="sm" disabled={Boolean(inventory.error) || points.length >= MAX_POINTS && !point} onClick={() => point ? openForm(point) : openForm(undefined, peer.address)}>{point ? 'Edit manual' : 'Map manually'}</Button></div></TableCell>
        </TableRow>;
      })}{!peers.length && <TableRow><TableCell colSpan={6} className="h-24 text-center text-muted-foreground">{!network ? 'No network sample supplied. Saved manual inventory still works.' : connections.length ? 'No remote destinations match these filters. Null and wildcard destinations are excluded.' : 'No remote peers in the current sample.'}</TableCell></TableRow>}</TableBody></Table><Pager page={currentPeerPage} count={peers.length} onPage={setPeerPage} />
    </CardContent></Card>
    {selectedPeer && <Card data-testid="atlas-selected-peer"><CardHeader><div className="flex items-start justify-between gap-3"><div><CardTitle className="break-all">{selectedPeer.address}</CardTitle><CardDescription className="mt-2">Selected sampled endpoint · {geoStatus(selectedPeer)}</CardDescription></div><Button variant="ghost" size="sm" onClick={() => { setSelectedAddress(null); setSelectedId(null); }}>Close details</Button></div></CardHeader><CardContent className="space-y-4"><PeerFacts peer={selectedPeer} />{selectedGeo && <p className="text-xs text-muted-foreground">Source: ipwho.is · looked up {new Date(selectedGeo.lookedUpAt).toLocaleString()} · {selectedGeo.asn || 'ASN unavailable'} · {selectedGeo.organization || 'Organization unavailable'}</p>}{onDiagnose && <div className="flex gap-2"><Button variant="outline" onClick={() => onDiagnose(selectedPeer.address, 'ping')}>Open Ping</Button><Button variant="outline" onClick={() => onDiagnose(selectedPeer.address, 'mtr')}>Open MTR</Button></div>}</CardContent></Card>}

    <Accordion type="single" collapsible className="rounded-lg border px-4"><AccordionItem value="privacy" className="border-0"><AccordionTrigger>Privacy, local interfaces, and import format</AccordionTrigger><AccordionContent className="space-y-4 text-sm text-muted-foreground"><p>Manual names, hosts, and coordinates stay in browser storage. Public numeric IPs are looked up through the local server only after explicit geography consent. Results stay in this mounted visit, separate from manual inventory; approximate IP geography does not identify a person or exact server. Private, loopback, reserved, and unknown peers are never inferred. Online basemap consent does not enable IP lookup. Mercator clips the poles; use globe or the table for polar coordinates.</p><p>Import up to 500 total points / 1 MiB as a JSON endpoint array, <code>{'{"version":1,"endpoints":[…]}'}</code>, or a GeoJSON Point FeatureCollection. Each point needs name, address, role (origin or endpoint), longitude, and latitude; GeoJSON uses [longitude, latitude] and name/address/role properties. Only one origin and one location per address. Imports append atomically; duplicates or invalid coordinates reject the entire import without replacing existing data. Exports include private hostnames and coordinates; share carefully.</p><Separator /><h3 className="font-medium text-foreground">Reported interfaces — addresses, not locations</h3>{!network?.interfaces.length ? <p>No interface snapshot supplied.</p> : <Table><TableHeader><TableRow><TableHead>Interface</TableHead><TableHead>Address</TableHead><TableHead>Family</TableHead><TableHead>Manual mapping</TableHead></TableRow></TableHeader><TableBody>{network.interfaces.map((item, index) => <TableRow key={item.name + item.address + index}><TableCell>{item.name}{item.internal ? ' · internal' : ''}</TableCell><TableCell className="font-mono text-xs">{item.address}</TableCell><TableCell>{item.family}</TableCell><TableCell><Button variant="outline" size="sm" disabled={!maybeHost(item.address) || mapped.has(maybeHost(item.address) ?? '') || Boolean(inventory.error) || points.length >= MAX_POINTS} onClick={() => openForm(undefined, item.address, origin ? 'endpoint' : 'origin')}>{mapped.has(maybeHost(item.address) ?? '') ? 'Already mapped' : 'Assign known coordinates'}</Button></TableCell></TableRow>)}</TableBody></Table>}</AccordionContent></AccordionItem></Accordion>

    <Dialog open={Boolean(draft)} onOpenChange={open => { if (!open) setDraft(null); }}><DialogContent className="max-h-[90vh] overflow-y-auto"><DialogHeader><DialogTitle>{points.some(point => point.id === draft?.id) ? 'Edit manual location' : 'Add manual location'}</DialogTitle><DialogDescription>This form saves only coordinates you supply, not provider results. Enter coordinates you know; localhost and private hosts are allowed only with explicit coordinates.</DialogDescription></DialogHeader>{draft && <form onSubmit={event => { event.preventDefault(); save(); }} className="space-y-4"><div className="space-y-2"><Label htmlFor="atlas-name">Endpoint name</Label><Input id="atlas-name" value={draft.name} maxLength={80} required autoFocus onChange={event => setDraft({ ...draft, name: event.target.value })} placeholder="A name you recognize" /></div><div className="space-y-2"><Label htmlFor="atlas-live-address">Choose an observed address (optional)</Label><Select value={addresses.includes(draft.address) ? draft.address : '__custom__'} onValueChange={value => setDraft({ ...draft, address: value === '__custom__' ? '' : value })}><SelectTrigger id="atlas-live-address" className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="__custom__">Custom host / IP</SelectItem>{addresses.map(address => <SelectItem key={address} value={address}>{address}</SelectItem>)}</SelectContent></Select></div><div className="space-y-2"><Label htmlFor="atlas-address">Host or IP address</Label><Input id="atlas-address" value={draft.address} required maxLength={320} onChange={event => setDraft({ ...draft, address: event.target.value })} placeholder="localhost, private IP, or example.com" spellCheck={false} autoCapitalize="none" /><p className="text-xs text-muted-foreground">No URL, port, or path. Saving this field does not make a network request.</p></div><div className="grid grid-cols-2 gap-3"><div className="space-y-2"><Label htmlFor="atlas-longitude">Longitude</Label><Input id="atlas-longitude" type="number" step="any" min={-180} max={180} required value={draft.longitude} onChange={event => setDraft({ ...draft, longitude: event.target.value })} placeholder="−180 to 180" /></div><div className="space-y-2"><Label htmlFor="atlas-latitude">Latitude</Label><Input id="atlas-latitude" type="number" step="any" min={-90} max={90} required value={draft.latitude} onChange={event => setDraft({ ...draft, latitude: event.target.value })} placeholder="−90 to 90" /></div></div><div className="space-y-2"><Label htmlFor="atlas-role">Role</Label><Select value={draft.role} onValueChange={role => setDraft({ ...draft, role: role as Endpoint['role'] })}><SelectTrigger id="atlas-role" className="w-full"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="origin">Origin · one per inventory</SelectItem><SelectItem value="endpoint">Endpoint</SelectItem></SelectContent></Select></div>{formError && <Alert variant="destructive"><AlertTitle>Location was not saved</AlertTitle><AlertDescription>{formError}</AlertDescription></Alert>}<DialogFooter><Button variant="outline" type="button" onClick={() => setDraft(null)}>Cancel</Button><Button type="submit">Save manual location</Button></DialogFooter></form>}</DialogContent></Dialog>

    <Dialog open={geoConsentOpen} onOpenChange={setGeoConsentOpen}><DialogContent><DialogHeader><DialogTitle>Share public peer IPs for approximate geography?</DialogTitle><DialogDescription>Your local server sends matching public numeric destination IP addresses to ipwho.is over HTTPS. The provider can learn those IPs and your server's public IP. Private, loopback, reserved, and unknown peers are excluded. This is separate from online basemap consent.</DialogDescription></DialogHeader><Alert><ShieldCheck /><AlertTitle>Per-visit, bounded, and optional</AlertTitle><AlertDescription>Up to 128 distinct public IPs in small progressive batches. Results are provider estimates, not precise device locations. Names, processes, and ports are not sent. Consent and results are held only in this mounted atlas view; no browser storage or automatic retries. Global Live off pauses new requests.</AlertDescription></Alert><DialogFooter><Button variant="outline" onClick={() => setGeoConsentOpen(false)}>Do not share IPs</Button><Button onClick={() => { setGeoEnabled(true); setGeoConsentOpen(false); }}>Allow ipwho.is for this visit</Button></DialogFooter></DialogContent></Dialog>

    <Dialog open={consentOpen} onOpenChange={setConsentOpen}><DialogContent><DialogHeader><DialogTitle>Allow an online basemap for this view?</DialogTitle><DialogDescription>CARTO styles, map tiles, glyphs, and sprites load from CARTO and its providers, including OpenStreetMap-derived data. Requests reveal your IP address and the viewed map area. Endpoint names and addresses are not deliberately submitted, but tile requests can reveal the locations you view.</DialogDescription></DialogHeader><Alert><ShieldCheck /><AlertTitle>Offline is the default</AlertTitle><AlertDescription>Consent is not saved. Turn the online basemap off anytime to return to local grid and inventory only. Map attribution remains visible while online.</AlertDescription></Alert><DialogFooter><Button variant="outline" onClick={() => setConsentOpen(false)}>Stay offline</Button><Button onClick={() => { setOnline(true); setMapProblem(false); setConsentOpen(false); }}>Allow CARTO in this view</Button></DialogFooter></DialogContent></Dialog>

    <Dialog open={importOpen} onOpenChange={open => { setImportOpen(open); if (!open) { importSequence.current++; setImporting(null); setImportBusy(false); } }}><DialogContent><DialogHeader><DialogTitle>Import known locations</DialogTitle><DialogDescription>JSON or GeoJSON, up to 1 MiB and 500 total endpoints. Append only; validation errors leave the current inventory unchanged.</DialogDescription></DialogHeader><div className="space-y-2"><Label htmlFor="atlas-import">Inventory file</Label><Input id="atlas-import" type="file" accept=".json,.geojson,application/json,application/geo+json" onChange={event => void loadFile(event.target.files?.[0])} /></div>{importBusy && <p role="status" className="text-sm text-muted-foreground">Validating file locally…</p>}{importing && <p role="status" className="text-sm">{importing.length} validated locations ready to append. Hosts already in your inventory and a second origin will be rejected.</p>}{importError && <Alert variant="destructive"><AlertTitle>Import rejected</AlertTitle><AlertDescription>{importError} Existing inventory is unchanged.</AlertDescription></Alert>}<DialogFooter><Button variant="outline" onClick={() => setImportOpen(false)}>Cancel</Button><Button disabled={!importing || importBusy || Boolean(inventory.error)} onClick={appendImport}>Append locations</Button></DialogFooter></DialogContent></Dialog>

    <Dialog open={Boolean(deleting)} onOpenChange={open => { if (!open) setDeleting(null); }}><DialogContent><DialogHeader><DialogTitle>{deleting === 'reset' ? 'Reset invalid inventory?' : 'Delete saved location?'}</DialogTitle><DialogDescription>{deleting === 'reset' ? 'This removes the stored invalid atlas from this browser. Download a recovery copy first; this cannot be undone.' : 'Remove ' + (deleting?.name ?? '') + ' from this browser inventory. Live connections are never changed.'}</DialogDescription></DialogHeader><DialogFooter><Button variant="outline" onClick={() => setDeleting(null)}>Cancel</Button><Button variant="destructive" onClick={() => { if (!deleting) return; setStored(deleting === 'reset' ? [] : points.filter(point => point.id !== deleting.id)); if (deleting === 'reset' || selectedId === deleting.id) setSelectedId(null); setDeleting(null); }}>Confirm delete</Button></DialogFooter></DialogContent></Dialog>
  </div></TooltipProvider>;
}

export default Atlas;
