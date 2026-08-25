function escapeRegexChar(char: string): string {
  return /[.+^${}()|[\]\\]/.test(char) ? `\\${char}` : char;
}

export function globToRegExp(glob: string): RegExp {
  const normalized = glob.replace(/\\/g, '/');
  let out = '^';
  for (let i = 0; i < normalized.length; i += 1) {
    const char = normalized[i]!;
    const next = normalized[i + 1];
    const afterNext = normalized[i + 2];
    if (char === '*' && next === '*' && afterNext === '/') {
      out += '(?:.*/)?';
      i += 2;
    } else if (char === '*' && next === '*') {
      out += '.*';
      i += 1;
    } else if (char === '*') {
      out += '[^/]*';
    } else if (char === '?') {
      out += '[^/]';
    } else {
      out += escapeRegexChar(char);
    }
  }
  return new RegExp(`${out}$`);
}

export function matchesAny(path: string, globs: string[]): boolean {
  const normalized = path.replace(/\\/g, '/');
  return globs.some((glob) => globToRegExp(glob).test(normalized));
}
