// URL facts are internal abstract values, never source text in the result snapshot.
const fixed = () => ({ kind: 'FIXED_DESTINATION', controlledPart: 'PATH_QUERY_OR_NONE' });
export const unresolvedDestination = () => ({ kind: 'UNRESOLVED_DESTINATION', controlledPart: 'UNKNOWN' });
const controlled = part => ({ kind: 'INPUT_IN_DESTINATION', controlledPart: part });
const literal = v => v?.tag === 'constant' && Object.hasOwn(v, 'constant') && !v.unknown;
function absolute(text) {
  try { const u = new URL(text); return ['http:', 'https:'].includes(u.protocol) && Boolean(u.hostname); }
  catch { return false; }
}
function fixedPrefix(prefix) {
  // Require an authority terminator before the first dynamic segment, including URL backslash semantics.
  return typeof prefix === 'string' && /^https?:\/\/[^/\\?#\s]+[/\\?#]/i.test(prefix) && absolute(prefix);
}
export function destinationOf(v) {
  if (!v) return unresolvedDestination();
  if (v.ref?.http && ['url', 'outboundRequest'].includes(v.tag)) {
    if (v.ref.unknown || v.unknown) return unresolvedDestination();
    if (v.ref.checks?.protocol && v.ref.checks?.hostname)
      return { kind: 'ALLOWLISTED_DESTINATION', controlledPart: 'PATH_QUERY_OR_NONE' };
    if (Object.keys(v.ref.checks ?? {}).length) return unresolvedDestination();
    return v.ref.http;
  }
  if (fixedPrefix(v.urlPrefix)) return fixed();
  if (v.unknown) return unresolvedDestination();
  if (v.destination) return v.destination;
  if (literal(v)) return typeof v.constant === 'string' && absolute(v.constant) ? fixed() : unresolvedDestination();
  if (v.trace?.length && ['input', 'route', 'urlText'].includes(v.tag)) return controlled('WHOLE_URL');
  return unresolvedDestination();
}
export function joinDestinations(values) {
  const shapes = values.map(destinationOf);
  if (shapes.some(d => d.kind === 'UNRESOLVED_DESTINATION')) return unresolvedDestination();
  if (shapes.some(d => d.kind === 'INPUT_IN_DESTINATION')) return controlled('WHOLE_URL_OR_HOST');
  if (shapes.every(d => d.kind === 'FIXED_DESTINATION')) return fixed();
  return unresolvedDestination();
}
export function concatenatedDestination(left, right) {
  const prefix = literal(left) && typeof left.constant === 'string' ? left.constant : left.urlPrefix;
  if (fixedPrefix(prefix)) return { urlPrefix: prefix, destination: fixed() };
  const traced = (left.trace?.length || right.trace?.length) && !left.unknown && !right.unknown;
  if (traced && typeof prefix === 'string' && /^(?:https?:)?\/\/[^/\\?#\s]*$/i.test(prefix))
    return { urlPrefix: prefix, destination: controlled('HOST_OR_AUTHORITY') };
  if (traced && (prefix === '' || prefix == null)) {
    const leading = literal(left) && left.constant === '' ? right : left;
    if (destinationOf(leading).kind === 'INPUT_IN_DESTINATION')
      return { urlPrefix: prefix, destination: controlled('WHOLE_URL') };
  }
  // A single leading slash may become //host (or /\host); a literal path segment cannot.
  return { urlPrefix: prefix, destination: unresolvedDestination() };
}
export function constructedUrl(input, base) {
  const direct = destinationOf(input);
  if (!base || direct.kind === 'FIXED_DESTINATION') return direct;
  if (literal(input) && typeof input.constant === 'string' && literal(base) && typeof base.constant === 'string') {
    try { return absolute(new URL(input.constant, base.constant).href) ? fixed() : unresolvedDestination(); }
    catch { return unresolvedDestination(); }
  }
  const prefix = literal(input) ? input.constant : input.urlPrefix;
  if (typeof prefix === 'string' && (/^\/[^/\\]/.test(prefix) || /^[?#]/.test(prefix))) return destinationOf(base);
  if (!input.unknown && input.trace?.length && (prefix === '/' || prefix == null || prefix === '')) return controlled('WHOLE_URL_OR_HOST');
  return direct;
}
