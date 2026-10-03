/** Search over secrets and their keys.
 *
 *  A search is almost always for a key -- AWS_ACCESS_KEY_ID, DB_PASS -- and
 *  the answer is the few keys that match, not every key of every Secret that
 *  happens to contain one of them. So when the query matches keys, only those
 *  keys are shown; when it matches only a Secret's name or namespace, the
 *  whole Secret is. Results are ranked: an exact key first, then a key that
 *  starts with the query, then one that contains it, then name/namespace
 *  matches -- ties alphabetical, so the same search always reads the same. */

export interface Searchable {
  name: string;
  namespace: string;
  keys: string[];
  /** Extra fields that count as a name match (an ExternalSecret's store). */
  extra?: string[];
}

export interface SecretMatch<T extends Searchable> {
  item: T;
  /** The keys to show, in display order. */
  keys: string[];
  /** Keys of the Secret not shown because they did not match. */
  hidden: number;
  rank: number;
}

const RANK_NAME = 3;

/** 0 exact, 1 prefix, 2 contains, -1 no match. Case-insensitive. */
export function keyRank(key: string, q: string): number {
  const k = key.toLowerCase();
  if (k === q) return 0;
  if (k.startsWith(q)) return 1;
  if (k.includes(q)) return 2;
  return -1;
}

const byName = (a: Searchable, b: Searchable) =>
  a.namespace.localeCompare(b.namespace) || a.name.localeCompare(b.name);

export function searchSecrets<T extends Searchable>(items: T[], query: string): SecretMatch<T>[] {
  const q = query.trim().toLowerCase();
  const sortedKeys = (keys: string[]) => [...keys].sort((a, b) => a.localeCompare(b));

  if (!q) {
    return [...items].sort(byName).map(item => ({ item, keys: sortedKeys(item.keys), hidden: 0, rank: RANK_NAME }));
  }

  const out: SecretMatch<T>[] = [];
  for (const item of items) {
    const ranked = item.keys
      .map(k => ({ k, r: keyRank(k, q) }))
      .filter(x => x.r >= 0)
      .sort((a, b) => a.r - b.r || a.k.localeCompare(b.k));
    if (ranked.length > 0) {
      out.push({ item, keys: ranked.map(x => x.k), hidden: item.keys.length - ranked.length, rank: ranked[0].r });
      continue;
    }
    const nameHit = [item.name, item.namespace, ...(item.extra ?? [])].some(f => f.toLowerCase().includes(q));
    if (nameHit) out.push({ item, keys: sortedKeys(item.keys), hidden: 0, rank: RANK_NAME });
  }
  return out.sort((a, b) => a.rank - b.rank || byName(a.item, b.item));
}
