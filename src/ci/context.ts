import type { CiContext, CiProvider, SentryCodeConfig } from '../core/types.js';

type Env = Record<string, string | undefined>;
function nonEmpty(value: string | undefined): string | undefined { return value && value.trim() ? value.trim() : undefined; }
function assign(ctx: CiContext, key: keyof Pick<CiContext,'baseRef'|'headRef'|'branch'|'repository'|'buildId'|'jobId'>, value: string | undefined): void {
  if (value) ctx[key] = value;
}

export function detectCi(config: SentryCodeConfig, env: Env = process.env): CiContext {
  if (!config.ci.enabled) return { provider:'local', detected:false, pullRequest:false };
  const forced = config.ci.provider;
  let provider: CiProvider = 'local';
  if (forced !== 'auto') provider = forced;
  else if (env.GITHUB_ACTIONS === 'true') provider = 'github';
  else if (env.GITLAB_CI === 'true') provider = 'gitlab';
  else if (env.TF_BUILD === 'True' || env.TF_BUILD === 'true') provider = 'azure-devops';
  else if (env.JENKINS_URL || env.BUILD_ID) provider = 'jenkins';
  else if (env.CI) provider = 'generic';

  const ctx: CiContext = { provider, detected: provider !== 'local', pullRequest: false };
  if (provider === 'github') {
    ctx.pullRequest = Boolean(env.GITHUB_BASE_REF);
    assign(ctx,'baseRef',nonEmpty(env.GITHUB_BASE_REF));
    assign(ctx,'headRef',nonEmpty(env.GITHUB_SHA) ?? nonEmpty(env.GITHUB_HEAD_REF));
    assign(ctx,'branch',nonEmpty(env.GITHUB_REF_NAME));
    assign(ctx,'repository',nonEmpty(env.GITHUB_REPOSITORY));
    assign(ctx,'buildId',nonEmpty(env.GITHUB_RUN_ID));
    assign(ctx,'jobId',nonEmpty(env.GITHUB_JOB));
  } else if (provider === 'gitlab') {
    ctx.pullRequest = Boolean(env.CI_MERGE_REQUEST_IID);
    assign(ctx,'baseRef',nonEmpty(env.CI_MERGE_REQUEST_TARGET_BRANCH_NAME));
    assign(ctx,'headRef',nonEmpty(env.CI_COMMIT_SHA));
    assign(ctx,'branch',nonEmpty(env.CI_COMMIT_REF_NAME));
    assign(ctx,'repository',nonEmpty(env.CI_PROJECT_PATH));
    assign(ctx,'buildId',nonEmpty(env.CI_PIPELINE_ID));
    assign(ctx,'jobId',nonEmpty(env.CI_JOB_ID));
  } else if (provider === 'azure-devops') {
    ctx.pullRequest = Boolean(env.SYSTEM_PULLREQUEST_PULLREQUESTID);
    assign(ctx,'baseRef',nonEmpty(env.SYSTEM_PULLREQUEST_TARGETBRANCH)?.replace(/^refs\/heads\//, ''));
    assign(ctx,'headRef',nonEmpty(env.BUILD_SOURCEVERSION));
    assign(ctx,'branch',nonEmpty(env.BUILD_SOURCEBRANCHNAME));
    assign(ctx,'repository',nonEmpty(env.BUILD_REPOSITORY_NAME));
    assign(ctx,'buildId',nonEmpty(env.BUILD_BUILDID));
    assign(ctx,'jobId',nonEmpty(env.SYSTEM_JOBID));
  } else if (provider === 'jenkins') {
    ctx.pullRequest = Boolean(env.CHANGE_ID);
    assign(ctx,'baseRef',nonEmpty(env.CHANGE_TARGET));
    assign(ctx,'headRef',nonEmpty(env.GIT_COMMIT));
    assign(ctx,'branch',nonEmpty(env.BRANCH_NAME) ?? nonEmpty(env.GIT_BRANCH));
    assign(ctx,'buildId',nonEmpty(env.BUILD_ID));
    assign(ctx,'jobId',nonEmpty(env.BUILD_TAG));
  }
  return ctx;
}
