import type { ApplicationStateStore } from '../application/store.js';
import type { CraReportDeliveryEnqueueResult } from '../application/types.js';
import type { CraFindingReport } from './cra-reporting.js';
import { appendAuditEvent } from '../enterprise/audit.js';

export interface CraFindingPublisher {
  publish(report: CraFindingReport): Promise<{ statusCode: number }>;
}

type CraDeliveryStore = Pick<ApplicationStateStore,
  'enqueueCraReportDelivery' | 'listPendingCraReportDeliveries' | 'recordCraReportDeliveryAttempt'>;

export interface CraDeliveryOptions {
  maxAttempts: number;
  retryDelayMs: number;
  batchSize?: number;
}

function asCraFindingReport(value: Record<string, unknown>): CraFindingReport {
  const report = value as unknown as CraFindingReport;
  if (!report || report.schemaVersion !== 1 || typeof report.reportId !== 'string' || typeof report.tenant !== 'string' || typeof report.project !== 'string') {
    throw new Error('Invalid persisted CRA finding report payload');
  }
  return report;
}

export async function enqueueCraFindingReports(store: CraDeliveryStore, reports: CraFindingReport[]): Promise<CraReportDeliveryEnqueueResult[]> {
  const queued: CraReportDeliveryEnqueueResult[] = [];
  for (const report of reports) {
    queued.push(await store.enqueueCraReportDelivery({
      reportId: report.reportId,
      tenant: report.tenant,
      project: report.project,
      findingId: report.finding.id,
      runId: report.correlation.runId,
      payload: report as unknown as Record<string, unknown>
    }));
  }
  return queued;
}

export async function deliverPendingCraFindingReports(args: {
  store: CraDeliveryStore;
  publisher: CraFindingPublisher;
  tenant: string;
  project: string;
  options: CraDeliveryOptions;
  root: string;
  auditLogFile: string;
  auditSigningPrivateKeyFile?: string;
  now?: Date;
}): Promise<{ attempted: number; delivered: number; failed: number }> {
  const now = args.now ?? new Date();
  const pending = await args.store.listPendingCraReportDeliveries(
    args.tenant,
    args.project,
    args.options.maxAttempts,
    now.toISOString(),
    args.options.batchSize ?? 100
  );
  let delivered = 0;
  let failed = 0;
  for (const record of pending) {
    const report = asCraFindingReport(record.payload);
    try {
      const result = await args.publisher.publish(report);
      await args.store.recordCraReportDeliveryAttempt(record.reportId, { delivered: true, responseStatus: result.statusCode });
      delivered += 1;
      await appendAuditEvent(args.root, args.auditLogFile, 'cra.report.delivered', {
        reportId: record.reportId, findingId: record.findingId, runId: record.runId,
        tenant: record.tenant, project: record.project, responseStatus: result.statusCode
      }, undefined, args.auditSigningPrivateKeyFile);
    } catch (error) {
      const message = (error as Error).message;
      const nextAttemptAt = new Date(now.getTime() + args.options.retryDelayMs).toISOString();
      await args.store.recordCraReportDeliveryAttempt(record.reportId, { delivered: false, error: message, nextAttemptAt });
      failed += 1;
      await appendAuditEvent(args.root, args.auditLogFile, 'cra.report.delivery_failed', {
        reportId: record.reportId, findingId: record.findingId, runId: record.runId,
        tenant: record.tenant, project: record.project, error: message
      }, undefined, args.auditSigningPrivateKeyFile);
    }
  }
  return { attempted: pending.length, delivered, failed };
}
