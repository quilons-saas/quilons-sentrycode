import type { ScanReport } from '../core/types.js';
const level=(severity:string)=>severity==='critical'||severity==='high'?'error':severity==='medium'?'warning':'note';
export function renderSarif(report:ScanReport):string{
  const findings=report.scanners.flatMap(s=>s.findings);
  const rules=[...new Map(findings.map(f=>[`${f.scanner}:${f.ruleId}`,{id:`${f.scanner}:${f.ruleId}`,shortDescription:{text:f.title},fullDescription:{text:f.description},help:{text:f.remediation ?? f.description}}])).values()];
  return `${JSON.stringify({version:'2.1.0',$schema:'https://json.schemastore.org/sarif-2.1.0.json',runs:[{tool:{driver:{name:'QUILONS SentryCode',version:'0.1.0',rules}},results:findings.map(f=>({ruleId:`${f.scanner}:${f.ruleId}`,level:level(f.severity),message:{text:f.description},locations:f.location?[{physicalLocation:{artifactLocation:{uri:f.location.path},region:{startLine:f.location.line ?? 1,startColumn:f.location.column ?? 1}}}]:[]}))}]},null,2)}\n`;
}
