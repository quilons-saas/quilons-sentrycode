import type { ConsumerPayloadPublisher } from './delivery.js';

export class HttpJsonConsumerPublisher implements ConsumerPayloadPublisher {
  constructor(
    private readonly endpoint: string,
    private readonly token: string,
    private readonly timeoutMs: number,
    private readonly capabilityVersion = 'quilons.service-invocation.v1'
  ) {}

  async publish(payload: Record<string, unknown>): Promise<{ statusCode: number }> {
    if (!this.endpoint.trim()) throw new Error('consumer endpoint is required');
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(this.endpoint, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-quilons-capability-version': this.capabilityVersion,
          ...(this.token ? { authorization: `Bearer ${this.token}` } : {})
        },
        body: JSON.stringify(payload),
        signal: controller.signal
      });
      if (!response.ok) throw new Error(`Endpoint returned HTTP ${response.status}`);
      return { statusCode: response.status };
    } finally {
      clearTimeout(timer);
    }
  }
}
