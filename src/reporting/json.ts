import { mkdir, writeFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import type { ScanReport } from '../core/types.js';

export function renderJson(report: ScanReport): string {
  return `${JSON.stringify(report, null, 2)}\n`;
}

export async function writeJsonReport(root: string, path: string, report: ScanReport): Promise<string> {
  const absolute = resolve(root, path);
  await mkdir(dirname(absolute), { recursive: true });
  await writeFile(absolute, renderJson(report), 'utf8');
  return absolute;
}
