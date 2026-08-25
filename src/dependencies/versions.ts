function parts(version: string): number[] {
  return version.replace(/^v/, '').split(/[.+-]/).slice(0, 3).map((item) => Number.parseInt(item, 10) || 0);
}

export function compareVersions(a: string, b: string): number {
  const av = parts(a);
  const bv = parts(b);
  for (let i = 0; i < 3; i += 1) {
    const diff = (av[i] ?? 0) - (bv[i] ?? 0);
    if (diff !== 0) return diff < 0 ? -1 : 1;
  }
  return 0;
}

export function satisfiesSimpleRange(version: string, range: string): boolean {
  const normalized = range.trim();
  if (!normalized || normalized === '*' || normalized.toLowerCase() === 'any') return true;
  for (const alternative of normalized.split('||').map((item) => item.trim())) {
    const clauses = alternative.split(/\s+/).filter(Boolean);
    if (clauses.every((clause) => satisfiesClause(version, clause))) return true;
  }
  return false;
}

function satisfiesClause(version: string, clause: string): boolean {
  if (clause.startsWith('^')) {
    const base = clause.slice(1);
    const [major = 0] = parts(base);
    return compareVersions(version, base) >= 0 && compareVersions(version, `${major + 1}.0.0`) < 0;
  }
  if (clause.startsWith('~')) {
    const base = clause.slice(1);
    const [major = 0, minor = 0] = parts(base);
    return compareVersions(version, base) >= 0 && compareVersions(version, `${major}.${minor + 1}.0`) < 0;
  }
  const match = clause.match(/^(<=|>=|<|>|=)?\s*(\d+(?:\.\d+){0,2})$/);
  if (!match) return version === clause;
  const operator = match[1] ?? '=';
  const target = match[2]!;
  const comparison = compareVersions(version, target);
  return operator === '=' ? comparison === 0 : operator === '<' ? comparison < 0 : operator === '<=' ? comparison <= 0 : operator === '>' ? comparison > 0 : comparison >= 0;
}
