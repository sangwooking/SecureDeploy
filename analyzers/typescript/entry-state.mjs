// Clone symbolic values, not parser/module objects. One graph per request entry
// preserves aliases and closure cycles without sharing effects across requests.
export function entryState(tick, canonicalFunctions) {
  const copies = new Map();
  const opaque = new Set(['node', 'mod', 'nativeMod']);
  function clone(original) {
    if (!original || typeof original !== 'object') return original;
    if (copies.has(original)) return copies.get(original);
    tick();
    const copy = original instanceof Map ? new Map() : original instanceof Set ? new Set()
      : Array.isArray(original) ? [] : {};
    copies.set(original, copy);
    if (original instanceof Map) {
      for (const [key, val] of original) { tick(); copy.set(key, clone(val)); }
    } else if (original instanceof Set) {
      for (const val of original) { tick(); copy.add(clone(val)); }
    } else {
      for (const [key, val] of Object.entries(original)) {
        tick(); copy[key] = opaque.has(key) ? val : clone(val);
      }
    }
    if (original.node && original.mod && original.closure)
      canonicalFunctions.set(copy, canonicalFunctions.get(original) ?? original);
    return copy;
  }
  return clone;
}
