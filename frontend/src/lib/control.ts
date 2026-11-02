// The console-only capability never travels in an HTTP URL or a public status response.
const key = 'portscope.control';
export function controlHeaders(): Record<string, string> {
  try {
    const token = sessionStorage.getItem(key);
    return token && /^[a-f0-9]{64}$/.test(token) ? { 'X-PortScope-Control': token } : {};
  } catch { return {}; }
}
function acceptControlLink() {
  try {
    const [route, query = ''] = location.hash.split('?');
    const params = new URLSearchParams(query), token = params.get('control');
    if (token && /^[a-f0-9]{64}$/.test(token)) sessionStorage.setItem(key, token);
    if (params.has('control')) { params.delete('control'); history.replaceState(null, '', location.pathname + location.search + route + (params.size ? '?' + params : '')); }
  } catch { /* Storage restrictions leave destructive actions locked. Monitoring still works. */ }
}
acceptControlLink();
window.addEventListener('hashchange', acceptControlLink);
