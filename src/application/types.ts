export type AdminRole = 'viewer' | 'engineer' | 'security_admin' | 'administrator';
export type WaiverWorkflowStatus = 'pending' | 'active' | 'rejected' | 'revoked' | 'expired';

export interface RegisteredRepository {
  id: string; tenant: string; project: string; name: string; rootPath: string; defaultBranch: string;
  enabled: boolean; createdAt: string; updatedAt: string;
}
export interface ManagedScannerSetting {
  repositoryId: string; scanner: string; enabled: boolean; required: boolean; failureMode: 'fail'|'warn'|'ignore'; updatedAt: string; updatedBy: string;
}
export interface ManagedPolicyAssignment {
  id: string; tenant: string; project: string; repositoryId: string | null; service: string | null;
  failOn: string[]; warnOn: string[]; requiredScanners: string[]; scannerFailureModes: Record<string,'fail'|'warn'|'ignore'>;
  lockedFields: string[]; version: number; updatedAt: string; updatedBy: string;
}
export interface WaiverWorkflowRecord {
  id: string; tenant: string; project: string; repositoryId: string | null; findingId: string | null;
  ruleId: string | null; scanner: string | null; path: string | null; fingerprint: string | null;
  reason: string; ticket: string | null; author: string; approver: string | null; status: WaiverWorkflowStatus;
  createdAt: string; expiresAt: string; decidedAt: string | null;
}
export interface IntegrationRecord {
  id: string; tenant: string; project: string; kind: string; name: string; enabled: boolean;
  configuration: Record<string, unknown>; secretReference: string | null; status: 'configured'|'connected'|'error'|'not_configured'; updatedAt: string; updatedBy: string;
}
export interface PrincipalRecord { id: string; subject: string; displayName: string; role: AdminRole; enabled: boolean; createdAt: string; updatedAt: string; }
export interface ApplicationAuditRecord { id: string; at: string; actor: string; action: string; entityType: string; entityId: string; detail: Record<string, unknown>; }
export interface ApplicationStateStatus { configured: boolean; connected: boolean; schemaVersion: number | null; detail: string; }

export type CraReportDeliveryStatus = 'pending' | 'delivered' | 'failed';
export interface CraReportDeliveryRecord {
  reportId: string; tenant: string; project: string; findingId: string; runId: string; payload: Record<string, unknown>;
  status: CraReportDeliveryStatus; attemptCount: number; responseStatus: number | null; lastAttemptAt: string | null;
  nextAttemptAt: string | null; lastError: string | null; deliveredAt: string | null; createdAt: string; updatedAt: string;
}
export interface CraReportDeliveryEnqueueResult { record: CraReportDeliveryRecord; created: boolean; }
