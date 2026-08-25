import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { SCHEMA_VERSION, type Finding, type ScannerContext, type ScannerPlugin, type ScannerResult } from '../../core/types.js';
import { stableId } from '../../utils/hash.js';
import { GitHubGovernanceProvider } from '../../git/github-provider.js';
const execFileAsync=promisify(execFile);
async function git(root:string,args:string[]):Promise<string>{ const {stdout}=await execFileAsync('git',args,{cwd:root,windowsHide:true}); return stdout.trim(); }
export class GitAssuranceScanner implements ScannerPlugin {
  readonly id='git-assurance'; readonly version='0.1.0';
  async scan(context:ScannerContext):Promise<ScannerResult>{
    const started=performance.now(); const at=context.now().toISOString();
    if(!context.config.gitAssurance.enabled) return {scanner:this.id,findings:[],evidence:[],durationMs:Math.round(performance.now()-started),status:'skipped',error:'scanner disabled by configuration'};
    const [name,email,signature]=await Promise.all([
      git(context.repository.root,['show','-s','--format=%an','HEAD']).catch(()=>''),
      git(context.repository.root,['show','-s','--format=%ae','HEAD']).catch(()=>''),
      git(context.repository.root,['log','-1','--format=%G?']).catch(()=>''),
    ]);
    const findings:Finding[]=[];
    const add=(ruleId:string,title:string,description:string,severity:Finding['severity'])=>{ const fp=stableId('fp',`${ruleId}|${context.repository.commitSha}`); findings.push({schemaVersion:SCHEMA_VERSION,id:stableId('finding',`${fp}|${at}`),type:'git-assurance',scanner:this.id,ruleId,title,description,severity,fingerprint:fp,detectedAt:at,remediation:'Correct repository/commit governance before release.'}); };
    if(context.config.gitAssurance.requireCleanTree && context.repository.isDirty) add('dirty-working-tree','Working tree is dirty','Release assurance requires a clean Git working tree.','high');
    const signed=['G','U'].includes(signature);
    if(context.config.gitAssurance.requireSignedCommit && !signed) add('unsigned-commit','HEAD commit is not verified','Policy requires a cryptographically signed HEAD commit.','high');
    const domains=context.config.gitAssurance.allowedEmailDomains.map(v=>v.toLowerCase());
    if(domains.length){ const domain=email.split('@')[1]?.toLowerCase() ?? ''; if(!domains.includes(domain)) add('author-email-domain','Commit author email domain is not allowed',`Commit author ${email || '(unknown)'} is outside the configured email domains.`,'medium'); }
    let governanceProvider = 'unavailable'; let protectedBranch: boolean | null = null; let requiredApprovals: number | null = null; let statusChecksRequired: boolean | null = null;
    if (context.config.gitAssurance.github.enabled && context.repository.branch) {
      const token = process.env[context.config.gitAssurance.github.tokenEnv] ?? '';
      if (!token) throw new Error(`GitHub governance is enabled but ${context.config.gitAssurance.github.tokenEnv} is not set`);
      const state = await new GitHubGovernanceProvider({ token, apiBaseUrl: context.config.gitAssurance.github.apiBaseUrl }).inspect(context.repository.root, context.repository.branch);
      governanceProvider = state.provider; protectedBranch = state.protected; requiredApprovals = state.requiredApprovals; statusChecksRequired = state.statusChecksRequired;
      if (context.config.gitAssurance.github.requireProtectedBranch && state.protected !== true) add('github.branch-unprotected','GitHub branch is not protected','Policy requires GitHub branch protection for the current branch.','high');
      if (state.requiredApprovals !== null && state.requiredApprovals < context.config.gitAssurance.github.minimumApprovals) add('github.insufficient-reviews','GitHub review protection is insufficient',`Branch requires ${state.requiredApprovals} approving review(s); policy requires ${context.config.gitAssurance.github.minimumApprovals}.`,'high');
      if (context.config.gitAssurance.github.requireStatusChecks && state.statusChecksRequired !== true) add('github.status-checks-missing','GitHub required status checks are not configured','Policy requires at least one required status check on the protected branch.','high');
    }
    return {scanner:this.id,findings,evidence:[{schemaVersion:SCHEMA_VERSION,id:stableId('evidence',`${context.repository.commitSha}|git-assurance|${at}`),type:'commit.verification',scanner:this.id,repository:context.repository.repository,commitSha:context.repository.commitSha,branch:context.repository.branch,generatedAt:at,findingIds:findings.map(f=>f.id),metadata:{scannerVersion:this.version,authorName:name,authorEmail:email,signatureStatus:signature || 'N',signatureVerified:signed,workingTreeClean:!context.repository.isDirty,governanceProvider,protectedBranch,requiredApprovals,statusChecksRequired}}],durationMs:Math.round(performance.now()-started)};
  }
}
