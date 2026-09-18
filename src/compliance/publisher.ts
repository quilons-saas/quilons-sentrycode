import type { CompliancePublication } from './contracts.js';
import type { CraFindingReport } from './cra-reporting.js';
import type { CraFindingPublisher } from './cra-delivery.js';

async function postJson(endpoint: string, token: string, timeoutMs: number, capabilityVersion: string, body: unknown): Promise<number> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'x-quilons-capability-version': capabilityVersion,
        ...(token ? { authorization: `Bearer ${token}` } : {})
      },
      body: JSON.stringify(body),
      signal: controller.signal
    });
    if (!response.ok) throw new Error(`Endpoint returned HTTP ${response.status}`);
    return response.status;
  } finally { clearTimeout(timer); }
}

export interface CompliancePublisher {
  publish(publication: CompliancePublication): Promise<void>;
}

export class HttpCompliancePublisher implements CompliancePublisher {
  constructor(private readonly endpoint: string, private readonly token: string, private readonly timeoutMs: number) {}

  async publish(publication: CompliancePublication): Promise<void> {
    await postJson(this.endpoint, this.token, this.timeoutMs, publication.evidence.apiVersion, publication);
  }
}

export class HttpCraFindingPublisher implements CraFindingPublisher {
  constructor(
    private readonly endpoint: string,
    private readonly token: string,
    private readonly timeoutMs: number,
    private readonly assessmentId: string
  ) {}

  async publish(report: CraFindingReport): Promise<{ statusCode: number }> {
    if (!this.assessmentId.trim()) throw new Error("CRA assessment ID is required for finding delivery");
    const statusCode = await postJson(
      this.endpoint,
      this.token,
      this.timeoutMs,
      "quilons.service-invocation.v1",
      {
        contractVersion: "quilons.service-invocation.v1",
        tenantId: report.tenant,
        appId: "quilons-sentrycode",
        operation: "cra.sentrycode.finding.ingest",
        actor: {
          actorType: "SERVICE",
          actorId: "quilons-sentrycode",
          permissions: ["cra.sentrycode.ingest"]
        },
        input: { assessmentId: this.assessmentId, report }
      }
    );
    return { statusCode };
  }
}
