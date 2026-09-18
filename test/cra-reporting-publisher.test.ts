import test from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { HttpCraFindingPublisher } from "../src/compliance/publisher.js";
import type { CraFindingReport } from "../src/compliance/cra-reporting.js";

function report(): CraFindingReport {
  return {
    schemaVersion: 1, contractVersion: "1.0.0", reportId: "report-1",
    source: { pluginId: "quilons.sentrycode", product: "QUILONS SentryCode", version: "0.1.0" },
    tenant: "tenant-a", project: "payments", repository: "payments-api",
    finding: { id: "finding-1", type: "vulnerability", scanner: "dependencies", ruleId: "CVE-2026-0001", title: "Critical dependency vulnerability", description: "Technical fact", severity: "critical", status: "active" },
    sourceRevision: { commitSha: "abc123", branch: "main" },
    evidenceReference: { apiVersion: "1.0.0", runId: "run-1", evidenceIds: ["evidence-1"], resourcePath: "/v1/runs/run-1/evidence" },
    correlation: { runId: "run-1" },
    timestamps: { detectedAt: "2026-09-18T07:00:00.000Z", scanCompletedAt: "2026-09-18T07:00:01.000Z", reportedAt: "2026-09-18T07:00:02.000Z" }
  };
}

test("CRA publisher invokes the governed CRA service operation instead of posting a raw report", async () => {
  let received: any;
  let authorization = "";
  const server = createServer(async (request, response) => {
    authorization = request.headers.authorization ?? "";
    const chunks: Buffer[] = [];
    for await (const chunk of request) chunks.push(Buffer.from(chunk));
    received = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    response.statusCode = 200;
    response.setHeader("content-type", "application/json");
    response.end(JSON.stringify({ result: { accepted: true } }));
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  assert.ok(address && typeof address === "object");
  try {
    const publisher = new HttpCraFindingPublisher(`http://127.0.0.1:${address.port}/api/v1/invoke`, "core-token", 5000, "assessment-1");
    assert.deepEqual(await publisher.publish(report()), { statusCode: 200 });
    assert.equal(authorization, "Bearer core-token");
    assert.equal(received.contractVersion, "quilons.service-invocation.v1");
    assert.equal(received.tenantId, "tenant-a");
    assert.equal(received.appId, "quilons-sentrycode");
    assert.equal(received.operation, "cra.sentrycode.finding.ingest");
    assert.deepEqual(received.actor, { actorType: "SERVICE", actorId: "quilons-sentrycode", permissions: ["cra.sentrycode.ingest"] });
    assert.equal(received.input.assessmentId, "assessment-1");
    assert.equal(received.input.report.reportId, "report-1");
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  }
});

test("CRA publisher refuses delivery without an explicit CRA assessment binding", async () => {
  const publisher = new HttpCraFindingPublisher("http://127.0.0.1:1/api/v1/invoke", "token", 100, "");
  await assert.rejects(publisher.publish(report()), /CRA assessment ID is required/);
});
