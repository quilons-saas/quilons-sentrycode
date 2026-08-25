import type { CompliancePublication } from './contracts.js';

export interface CompliancePublisher {
  publish(publication: CompliancePublication): Promise<void>;
}

export class HttpCompliancePublisher implements CompliancePublisher {
  constructor(private readonly endpoint: string, private readonly token: string, private readonly timeoutMs: number) {}

  async publish(publication: CompliancePublication): Promise<void> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-quilons-capability-version': publication.evidence.apiVersion,
          ...(this.token ? { authorization: `Bearer ${this.token}` } : {})
        },
        body: JSON.stringify(publication),
        signal: controller.signal
      });
      if (!response.ok) throw new Error(`Compliance endpoint returned HTTP ${response.status}`);
    } finally { clearTimeout(timer); }
  }
}
