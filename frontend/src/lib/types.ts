export interface Port {
  port:number; protocol:'http'|'https'|'tcp'|'pending'; probeStatus:'pending'|'done'|'timeout'|'error';
  url:string|null; title:string|null; statusCode:number|null; statusText:string|null;
  server:string|null; poweredBy:string|null; contentType:string|null; framework:string|null;
  responseTimeMs:number|null; latencyHistory:number[]; headers:Record<string,string>;
  bindAddresses:string[]; wildcard:boolean; pid:number; processName:string|null;
  category:'dev'|'app'|'system'; firstSeenAt:string; lastSeenAt:string; onlineForMs:number; isSelf:boolean; error:string|null;
}
export interface ActivityEvent { id:string; type:'start'|'online'|'offline'; port:number|null; pid:number|null; processName:string|null; title:string|null; category:'dev'|'app'|'system'|null; at:string }
export interface State {
  ok:boolean;
  meta:{app:string;version:string;hostname:string;platform:string;arch:string;serverPort:number;startedAt:string;scannedAt:string|null;scanDurationMs:number;scanCount:number;scanIntervalMs:number;isScanning:boolean;ready:boolean;pendingProbes:number;activeClients:number;uptimeMs:number;lastError:string|null};
  stats:{totalPorts:number;webPorts:number;httpsPorts:number;tcpOnlyPorts:number;processCount:number;newPorts:number;categoryCounts:{dev:number;app:number;system:number}};
  ports:Port[]; events:ActivityEvent[];
}
export interface NetworkConnection {id:string;protocol:'tcp'|'udp';localAddress:string;localPort:number;remoteAddress:string|null;remotePort:number|null;state:string;pid:number|null;processName:string|null;scope:'loopback'|'private'|'public'|'unknown'}
export interface NetworkInterface {name:string;address:string;family:string;internal:boolean;netmask:string;cidr:string|null;mac:string}
export interface NetworkSnapshot {limited?:boolean;totalObserved?:number;limit?:number;ok:boolean;scannedAt:string|null;platform:string;interfaces:NetworkInterface[];connections:NetworkConnection[];summary:{total:number;established:number;external:number;loopback:number;private:number;states:Record<string,number>};error:string|null}
export interface HistorySample {at:string;totalPorts:number;webPorts:number;tcpOnlyPorts:number;exposedPorts:number;processCount:number;avgResponseTimeMs:number|null;errorPorts:number}
export interface HistorySnapshot {ok:boolean;samples:HistorySample[];startedAt:string}
export interface ProcessDetail {pid:number;name:string|null;path:string|null;commandLine:string|null;parentPid:number|null;startedAt:string|null;workingSetMB:number|null}
export interface CheckResult {port:number;protocol:'http'|'https';path:string;expectedStatus:number;statusCode:number|null;responseTimeMs:number;healthy:boolean;checkedAt:string;error:string|null;headers:Record<string,string>}
export type DiagnosticKind = 'ping'|'mtr'|'tcp'|'tls';
export interface DiagnosticsSample {at:string;ms:number|null;status:string}
export interface DiagnosticsHop {ttl:number;address:string|null;status:string;sent:number;received:number;lost:number;lossPercent:number;lastMs:number|null;minMs:number|null;avgMs:number|null;maxMs:number|null;jitterMs:number|null;samples?:DiagnosticsSample[]}
export interface DiagnosticsTls {authorized:boolean;authorizationError:string|null;protocol:string|null;cipher:{name:string;standardName:string|null;version:string|null}|null;servername:string|null;subject:Record<string,string>|null;issuer:Record<string,string>|null;validFrom:string|null;validTo:string|null;fingerprint256:string|null;serialNumber:string|null;subjectAltName:string|null}
export interface DiagnosticsJob {id:string;kind:DiagnosticKind;target:string;address:string|null;family:4|6;port:number|null;status:'resolving'|'running'|'completed'|'cancelled'|'error';startedAt:string;updatedAt:string;finishedAt:string|null;error:string|null;cycle:number;cycles:number|null;continuous?:boolean;intervalMs:number;timeoutMs:number;maxHops:number;reached:boolean;timingMethod:string;hops:DiagnosticsHop[];samples:DiagnosticsSample[];tls?:DiagnosticsTls|null}
export interface DnsConfig {ok:boolean;servers:string[];platform:string;source:string}
export interface DnsAnswer {server:string;type:string;status:'answer'|'nodata'|'error';durationMs:number;answers:unknown[];error:string|null;name?:string}
export interface DnsSecResult {status:'validating'|'not-validating'|'inconclusive';explanation:string;tests:unknown[];server?:string}
export interface DnsResponse {ok:boolean;mode:'records'|'compare'|'dnssec'|'reverse';name:string|null;checkedAt:string;source:'backend';results:DnsAnswer[];dnssec?:DnsSecResult}
export interface GeoResult {ip:string;status:'located'|'private'|'unavailable';longitude:number|null;latitude:number|null;country:string|null;city:string|null;asn:string|null;organization:string|null;source:'ipwho.is';lookedUpAt:string;error:string|null}
