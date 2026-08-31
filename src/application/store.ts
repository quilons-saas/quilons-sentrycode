import type { ApplicationAuditRecord, ApplicationStateStatus, CraReportDeliveryEnqueueResult, CraReportDeliveryRecord, IntegrationRecord, ManagedPolicyAssignment, ManagedScannerSetting, PrincipalRecord, RegisteredRepository, WaiverWorkflowRecord } from './types.js';

export interface ApplicationStateStore {
  status(): Promise<ApplicationStateStatus>;
  migrate(): Promise<number>;
  listRepositories(tenant: string, project: string): Promise<RegisteredRepository[]>;
  upsertRepository(value: Omit<RegisteredRepository,'createdAt'|'updatedAt'>, actor: string): Promise<RegisteredRepository>;
  listScannerSettings(repositoryId: string): Promise<ManagedScannerSetting[]>;
  upsertScannerSetting(value: Omit<ManagedScannerSetting,'updatedAt'|'updatedBy'>, actor: string): Promise<ManagedScannerSetting>;
  listPolicies(tenant: string, project: string): Promise<ManagedPolicyAssignment[]>;
  upsertPolicy(value: Omit<ManagedPolicyAssignment,'version'|'updatedAt'|'updatedBy'>, actor: string): Promise<ManagedPolicyAssignment>;
  listWaivers(tenant: string, project: string): Promise<WaiverWorkflowRecord[]>;
  createWaiver(value: WaiverWorkflowRecord): Promise<WaiverWorkflowRecord>;
  transitionWaiver(id: string, status: 'active'|'rejected'|'revoked', actor: string): Promise<WaiverWorkflowRecord | null>;
  listIntegrations(tenant: string, project: string): Promise<IntegrationRecord[]>;
  upsertIntegration(value: Omit<IntegrationRecord,'updatedAt'|'updatedBy'>, actor: string): Promise<IntegrationRecord>;
  listPrincipals(): Promise<PrincipalRecord[]>;
  upsertPrincipal(value: PrincipalRecord): Promise<PrincipalRecord>;
  appendAudit(value: ApplicationAuditRecord): Promise<void>;
  listAudit(limit?: number): Promise<ApplicationAuditRecord[]>;
  enqueueCraReportDelivery(value: Pick<CraReportDeliveryRecord,'reportId'|'tenant'|'project'|'findingId'|'runId'|'payload'>): Promise<CraReportDeliveryEnqueueResult>;
  listPendingCraReportDeliveries(tenant: string, project: string, maxAttempts: number, now: string, limit?: number): Promise<CraReportDeliveryRecord[]>;
  recordCraReportDeliveryAttempt(reportId: string, value: { delivered: boolean; responseStatus?: number; error?: string; nextAttemptAt?: string }): Promise<CraReportDeliveryRecord | null>;
  close(): Promise<void>;
}

export class DisabledApplicationStateStore implements ApplicationStateStore {
  async status(): Promise<ApplicationStateStatus> { return { configured: false, connected: false, schemaVersion: null, detail: 'Set SENTRYCODE_DATABASE_URL to enable PostgreSQL-backed administration' }; }
  async migrate(): Promise<number> { throw new Error('DATABASE_NOT_CONFIGURED'); }
  private no(): never { throw new Error('DATABASE_NOT_CONFIGURED'); }
  async listRepositories(): Promise<RegisteredRepository[]> { return []; }
  async upsertRepository(): Promise<RegisteredRepository> { return this.no(); }
  async listScannerSettings(): Promise<ManagedScannerSetting[]> { return []; }
  async upsertScannerSetting(): Promise<ManagedScannerSetting> { return this.no(); }
  async listPolicies(): Promise<ManagedPolicyAssignment[]> { return []; }
  async upsertPolicy(): Promise<ManagedPolicyAssignment> { return this.no(); }
  async listWaivers(): Promise<WaiverWorkflowRecord[]> { return []; }
  async createWaiver(): Promise<WaiverWorkflowRecord> { return this.no(); }
  async transitionWaiver(): Promise<WaiverWorkflowRecord | null> { return this.no(); }
  async listIntegrations(): Promise<IntegrationRecord[]> { return []; }
  async upsertIntegration(): Promise<IntegrationRecord> { return this.no(); }
  async listPrincipals(): Promise<PrincipalRecord[]> { return []; }
  async upsertPrincipal(): Promise<PrincipalRecord> { return this.no(); }
  async appendAudit(): Promise<void> { return; }
  async listAudit(): Promise<ApplicationAuditRecord[]> { return []; }
  async enqueueCraReportDelivery(): Promise<CraReportDeliveryEnqueueResult> { return this.no(); }
  async listPendingCraReportDeliveries(): Promise<CraReportDeliveryRecord[]> { return []; }
  async recordCraReportDeliveryAttempt(): Promise<CraReportDeliveryRecord | null> { return this.no(); }
  async close(): Promise<void> { return; }
}
