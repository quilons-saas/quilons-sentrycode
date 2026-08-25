export function shannonEntropy(value: string): number {
  if (!value.length) return 0;
  const counts = new Map<string, number>();
  for (const char of value) counts.set(char, (counts.get(char) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / value.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

export function looksLikeHighEntropySecret(value: string, minLength: number): boolean {
  if (value.length < minLength || value.length > 256) return false;
  if (!/^[A-Za-z0-9+/=_\-.]+$/.test(value)) return false;
  if (!/[A-Za-z]/.test(value) || !/[0-9]/.test(value)) return false;
  return shannonEntropy(value) >= 4.0;
}
