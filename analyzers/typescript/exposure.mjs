// Metadata only; literals and environment names never enter observations or findings.
export const credentialShape = text => typeof text === 'string' &&
  /^(?:sb_secret_[A-Za-z0-9_-]{24,}|sk-(?:proj-)?[A-Za-z0-9_-]{24,}|gh[pousr]_[A-Za-z0-9]{30,}|xox[baprs]-[A-Za-z0-9-]{24,}|AKIA[A-Z0-9]{16})$/.test(text);
export function sources(v, depth = 0, seen = new Set()) {
  if (!v || depth > 3 || seen.has(v)) return [];
  seen.add(v);
  const children = v.ref?.properties ? [...v.ref.properties.values()].flatMap(c => sources(c, depth + 1, seen)) : [];
  return [...(v.exposures ?? []), ...children].filter((s, i, a) => a.findIndex(t => JSON.stringify(t) === JSON.stringify(s)) === i).slice(0, 20);
}
export function uncertain(v, depth = 0, seen = new Set()) {
  if (!v || depth > 3 || seen.has(v)) return depth > 3;
  seen.add(v);
  return Boolean(v.unknown || v.ref?.unknown || [...(v.ref?.properties?.values() ?? [])].some(c => uncertain(c, depth + 1, seen)));
}
export function trails(v, depth = 0, seen = new Set()) {
  if (!v || depth > 3 || seen.has(v)) return [];
  seen.add(v);
  return [...(v.exposureTrail ?? []), ...(v.ref?.properties ? [...v.ref.properties.values()].flatMap(c => trails(c, depth + 1, seen)) : [])].slice(0, 10);
}
