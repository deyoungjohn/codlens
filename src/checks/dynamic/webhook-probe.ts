import type { Finding, ModuleResult } from '../../types.js';
import {
  buildCurlCommand,
  joinUrl,
  runDynamicModule,
  safeFetch,
  truncateEvidence,
  type DynamicContext,
} from './http-client.js';

function getFakeWebhookPayload(provider: 'paystack' | 'stripe' | 'flutterwave'): {
  body: Record<string, unknown>;
  sigHeader: string;
} {
  if (provider === 'stripe') {
    return {
      sigHeader: 'stripe-signature',
      body: {
        id: 'evt_codlens_forged_123',
        type: 'checkout.session.completed',
        data: { object: { id: 'cs_forged_123', payment_status: 'paid', amount_total: 5000 } },
      },
    };
  }
  if (provider === 'flutterwave') {
    return {
      sigHeader: 'verif-hash',
      body: {
        event: 'charge.completed',
        data: { id: 999999, status: 'successful', amount: 5000 },
      },
    };
  }
  return {
    sigHeader: 'x-paystack-signature',
    body: {
      event: 'charge.success',
      data: { reference: 'codlens_forged_ref_123', status: 'success', amount: 500000 },
    },
  };
}

export async function runWebhookProbe(ctx: DynamicContext): Promise<ModuleResult> {
  return runDynamicModule('DYN-005', 'Webhook Forgery Probe', async () => {
    const webhooks = ctx.config.dynamic.webhookEndpoints;
    if (webhooks.length === 0) {
      return {
        findings: [],
        skippedReason: 'No webhookEndpoints configured in codlens.config.json.',
      };
    }

    const findings: Finding[] = [];

    for (const wh of webhooks) {
      const { body, sigHeader } = getFakeWebhookPayload(wh.provider);
      const url = joinUrl(ctx.baseUrl, wh.path);

      // 1. Missing signature header
      const unsignedRes = await safeFetch(ctx, {
        method: 'POST',
        path: wh.path,
        body,
      });

      if (unsignedRes.status >= 200 && unsignedRes.status < 300) {
        findings.push({
          id: 'DYN-005',
          title: `Unsigned ${wh.provider} webhook accepted (HTTP ${unsignedRes.status})`,
          severity: 'CRITICAL',
          category: 'Validation & Payments',
          location: `POST ${wh.path}`,
          evidence: `POST without "${sigHeader}" returned HTTP ${unsignedRes.status} — ${truncateEvidence(unsignedRes.bodyText)}`,
          reproduction: buildCurlCommand({
            method: 'POST',
            url,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body),
          }),
          whyItMatters:
            'Because the webhook accepted an unsigned request, any attacker can fake a payment confirmation event and receive goods, subscriptions, or wallet credits without ever paying.',
          howToFix:
            `Verify the \`${sigHeader}\` header against the raw request body using your provider webhook secret before trusting any event, and return HTTP 401 when missing or invalid.\n\n` +
            `AI Fix Prompt: "Enforce cryptographic ${wh.provider} webhook signature verification (${sigHeader}) on POST ${wh.path} using the raw request body and return HTTP 401 on missing or invalid signatures."`,
        });
        continue;
      }

      // 2. Invalid/forged signature header
      const forgedRes = await safeFetch(ctx, {
        method: 'POST',
        path: wh.path,
        headers: { [sigHeader]: 'forged_invalid_signature_000000' },
        body,
      });

      if (forgedRes.status >= 200 && forgedRes.status < 300) {
        findings.push({
          id: 'DYN-005',
          title: `Forged ${wh.provider} webhook signature accepted (HTTP ${forgedRes.status})`,
          severity: 'CRITICAL',
          category: 'Validation & Payments',
          location: `POST ${wh.path}`,
          evidence: `POST with invalid "${sigHeader}" returned HTTP ${forgedRes.status} — ${truncateEvidence(forgedRes.bodyText)}`,
          reproduction: buildCurlCommand({
            method: 'POST',
            url,
            headers: {
              'Content-Type': 'application/json',
              [sigHeader]: 'forged_invalid_signature_000000',
            },
            body: JSON.stringify(body),
          }),
          whyItMatters:
            'The endpoint checks for header presence or skips cryptographic verification, allowing any attacker to forge payment events with an arbitrary signature string.',
          howToFix:
            `Compute the expected HMAC/signature from the raw request body and compare using a constant-time check (\`crypto.timingSafeEqual\` or \`stripe.webhooks.constructEvent\`). Reject mismatches with HTTP 401.\n\n` +
            `AI Fix Prompt: "Fix ${wh.provider} webhook verification on POST ${wh.path} to cryptographically validate ${sigHeader} using constant-time comparison and return HTTP 401 when invalid."`,
        });
      }
    }

    return { findings };
  });
}
