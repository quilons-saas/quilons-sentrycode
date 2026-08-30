import { readFile } from 'node:fs/promises';
import { extname, relative } from 'node:path';
import { discoverFiles } from '../../core/files.js';
import { SCHEMA_VERSION, type Finding, type ScannerContext, type ScannerPlugin, type ScannerResult, type SastLanguage } from '../../core/types.js';
import { stableId } from '../../utils/hash.js';

interface Rule { id: string; languages: SastLanguage[]; severity: Finding['severity']; pattern: RegExp; title: string; description: string; remediation: string; }
const RULES: Rule[] = [
  { id: 'js-eval', languages: ['javascript','typescript'], severity: 'high', pattern: /\beval\s*\(/g, title: 'Dynamic eval usage', description: 'Use of eval can execute untrusted code.', remediation: 'Replace eval with explicit parsing or dispatch.' },
  { id: 'js-child-process-shell', languages: ['javascript','typescript'], severity: 'high', pattern: /(?:\bexecSync\s*\(|\bchild_process\.exec\s*\()/g, title: 'Shell command execution', description: 'Shell execution can become command injection when input is untrusted.', remediation: 'Prefer execFile/spawn with fixed arguments and validate external input.' },
  { id: 'js-insecure-random', languages: ['javascript','typescript'], severity: 'medium', pattern: /\bMath\.random\s*\(/g, title: 'Non-cryptographic randomness', description: 'Math.random is unsuitable for security-sensitive tokens.', remediation: 'Use node:crypto randomBytes/randomUUID for security-sensitive values.' },
  { id: 'py-eval', languages: ['python'], severity: 'high', pattern: /\beval\s*\(/g, title: 'Dynamic eval usage', description: 'Python eval can execute untrusted code.', remediation: 'Use safe parsing such as ast.literal_eval where appropriate.' },
  { id: 'py-shell-true', languages: ['python'], severity: 'high', pattern: /subprocess\.(?:run|Popen|call|check_output|check_call)\s*\([^\n]*shell\s*=\s*True/g, title: 'subprocess shell=True', description: 'shell=True increases command-injection risk.', remediation: 'Pass an argument list and keep shell=False.' },
  { id: 'py-pickle-load', languages: ['python'], severity: 'high', pattern: /\bpickle\.loads?\s*\(/g, title: 'Unsafe pickle deserialization', description: 'Pickle deserialization can execute arbitrary code.', remediation: 'Use a safe serialization format for untrusted data.' },
  { id: 'java-runtime-exec', languages: ['java'], severity: 'high', pattern: /\bRuntime\.getRuntime\(\)\.exec\s*\(/g, title: 'Runtime command execution', description: 'Runtime.exec can become command injection when arguments contain untrusted data.', remediation: 'Use a fixed ProcessBuilder argument list and validate external input.' },
  { id: 'java-object-deserialization', languages: ['java'], severity: 'high', pattern: /\bObjectInputStream\b|\.readObject\s*\(/g, title: 'Java native deserialization', description: 'Native Java deserialization of untrusted data can enable code execution.', remediation: 'Use a constrained data format and avoid deserializing untrusted Java objects.' },
  { id: 'java-weak-digest', languages: ['java'], severity: 'medium', pattern: /MessageDigest\.getInstance\s*\(\s*["'](?:MD5|SHA-?1)["']/gi, title: 'Weak cryptographic digest', description: 'MD5 and SHA-1 are unsuitable for security-sensitive integrity decisions.', remediation: 'Use SHA-256 or stronger where a cryptographic digest is required.' },
  { id: 'java-sql-concat', languages: ['java'], severity: 'high', pattern: /(?:executeQuery|executeUpdate|prepareStatement)\s*\([^\n;]*\+/g, title: 'SQL built by string concatenation', description: 'Concatenating values into SQL can enable SQL injection.', remediation: 'Use parameterized PreparedStatement values.' },
  { id: 'csharp-process-start', languages: ['csharp'], severity: 'high', pattern: /\bProcess\.Start\s*\(/g, title: 'Process execution', description: 'Process.Start can become command injection when arguments contain untrusted data.', remediation: 'Use fixed executables/argument lists and validate external input.' },
  { id: 'csharp-binaryformatter', languages: ['csharp'], severity: 'critical', pattern: /\bBinaryFormatter\b|\.Deserialize\s*\(/g, title: 'Unsafe .NET binary deserialization', description: 'BinaryFormatter-style deserialization is unsafe for untrusted data.', remediation: 'Use a safe serializer with explicit contract types.' },
  { id: 'csharp-weak-digest', languages: ['csharp'], severity: 'medium', pattern: /\b(?:MD5|SHA1)\.Create\s*\(/g, title: 'Weak cryptographic digest', description: 'MD5 and SHA-1 are unsuitable for security-sensitive integrity decisions.', remediation: 'Use SHA256 or stronger.' },
  { id: 'csharp-sql-concat', languages: ['csharp'], severity: 'high', pattern: /(?:SqlCommand|ExecuteSqlRaw)\s*\([^\n;]*\+/g, title: 'SQL built by string concatenation', description: 'Concatenating values into SQL can enable SQL injection.', remediation: 'Use parameterized SQL commands.' },
  { id: 'c-system-call', languages: ['c','cpp'], severity: 'high', pattern: /\bsystem\s*\(/g, title: 'Shell command execution', description: 'system() invokes a shell and can enable command injection when input is untrusted.', remediation: 'Avoid shell invocation; use a fixed executable and validated argument vector.' },
  { id: 'c-gets', languages: ['c','cpp'], severity: 'critical', pattern: /\bgets\s*\(/g, title: 'Unbounded input with gets', description: 'gets() cannot bound input and can cause a buffer overflow.', remediation: 'Use fgets or another bounded input API.' },
  { id: 'c-strcpy', languages: ['c','cpp'], severity: 'high', pattern: /\b(?:strcpy|strcat)\s*\(/g, title: 'Unbounded C string copy', description: 'Unbounded string copy/concatenation can overflow destination buffers.', remediation: 'Use a bounded API and validate destination capacity.' },
  { id: 'c-sprintf', languages: ['c','cpp'], severity: 'high', pattern: /\bsprintf\s*\(/g, title: 'Unbounded formatted output', description: 'sprintf can overflow a destination buffer.', remediation: 'Use snprintf with the actual destination size.' },
  { id: 'c-tmpnam', languages: ['c','cpp'], severity: 'high', pattern: /\btmpnam\s*\(/g, title: 'Insecure temporary file name', description: 'tmpnam is vulnerable to race conditions and predictable-name attacks.', remediation: 'Use a securely created temporary file API.' },
  { id: 'c-insecure-rand', languages: ['c','cpp'], severity: 'medium', pattern: /\brand\s*\(/g, title: 'Non-cryptographic randomness', description: 'rand() is unsuitable for security-sensitive randomness.', remediation: 'Use the platform cryptographic random-number generator.' },
];

function language(path: string): SastLanguage | null {
  const ext = extname(path).toLowerCase();
  if (ext === '.ts' || ext === '.tsx') return 'typescript';
  if (ext === '.js' || ext === '.jsx' || ext === '.mjs' || ext === '.cjs') return 'javascript';
  if (ext === '.py') return 'python';
  if (ext === '.java') return 'java';
  if (ext === '.cs') return 'csharp';
  if (ext === '.c' || ext === '.h') return 'c';
  if (['.cc','.cpp','.cxx','.c++','.hh','.hpp','.hxx'].includes(ext)) return 'cpp';
  return null;
}
function pos(content: string, index: number) { const before=content.slice(0,index).split('\n'); return { line: before.length, column: (before.at(-1)?.length ?? 0)+1 }; }

export class SastScanner implements ScannerPlugin {
  readonly id='sast'; readonly version='0.1.0';
  async scan(context: ScannerContext): Promise<ScannerResult> {
    const started=performance.now(); const detectedAt=context.now().toISOString();
    if (!context.config.sast.enabled) return { scanner:this.id, findings:[], evidence:[], durationMs:Math.round(performance.now()-started), status:'skipped', error:'scanner disabled by configuration' };
    const findings: Finding[]=[]; const files=await discoverFiles(context.repository.root, context.config, context.execution?.mode === 'incremental' ? context.execution.changedFiles : undefined); let scanned=0;
    for (const absolute of files) {
      const path=relative(context.repository.root,absolute).replace(/\\/g,'/'); const lang=language(path);
      if (!lang || !context.config.sast.languages.includes(lang)) continue;
      let content=''; try { content=await readFile(absolute,'utf8'); } catch { continue; } if (content.includes('\0')) continue; scanned++;
      for (const rule of RULES.filter(r=>r.languages.includes(lang))) {
        rule.pattern.lastIndex=0;
        for (const match of content.matchAll(rule.pattern)) {
          const location=pos(content,match.index ?? 0); const fingerprint=stableId('fp',`${rule.id}|${path}|${location.line}`);
          findings.push({ schemaVersion:SCHEMA_VERSION, id:stableId('finding',`${fingerprint}|${detectedAt}`), type:'sast', scanner:this.id, ruleId:rule.id, title:rule.title, description:rule.description, severity:rule.severity, location:{path,...location}, fingerprint, remediation:rule.remediation, detectedAt, metadata:{language:lang} });
        }
      }
    }
    const unique=[...new Map(findings.map(f=>[f.fingerprint,f])).values()];
    return { scanner:this.id, findings:unique, evidence:[{ schemaVersion:SCHEMA_VERSION, id:stableId('evidence',`${context.repository.commitSha}|sast|${detectedAt}`), type:'sast.scan', scanner:this.id, repository:context.repository.repository, commitSha:context.repository.commitSha, branch:context.repository.branch, generatedAt:detectedAt, findingIds:unique.map(f=>f.id), metadata:{scannerVersion:this.version, filesScanned:scanned, findingCount:unique.length, ruleCount:RULES.length} }], durationMs:Math.round(performance.now()-started) };
  }
}
