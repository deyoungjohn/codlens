import type { Finding, ModuleResult } from '../../types.js';
import {
  isCodeFile,
  isFrontendUiFile,
  isTestOrMockFile,
  runStaticModule,
  type StaticScanContext,
} from './utils.js';

const WEBHOOK_ROUTE_REGEX =
  /(?:webhooks?\/(?:paystack|stripe|flutterwave)|x-paystack-signature|stripe-signature|verif-hash)/i;

const SIGNATURE_VERIFY_REGEX =
  /\b(?:createHmac|constructEvent|timingSafeEqual|verifySignature|hmac\.new|hmac\.compare_digest)\b/i;

const CHECKOUT_CONTEXT_REGEX =
  /\b(?:checkout|payment|charge|order|invoice|subscribe|paystack|stripe)\b/i;

const CLIENT_PRICE_REGEX =
  /(?:req\.body|request\.body)\.(?:price|amount|total|unitPrice|totalPrice)\b|\{\s*[^}]*\b(?:price|amount|total)\b[^}]*\}\s*=\s*(?:req\.body|request\.body|await\s+req(?:uest)?\.json\(\))/;

const DB_PRICE_LOOKUP_REGEX =
  /\b(?:findUnique|findFirst|findById|findOne|SELECT\s+.*price|products?\[|catalog\[|getProduct|getPrice|PRICES\[|ITEM_PRICES)\b/i;

export async function runPaymentScan(ctx: StaticScanContext): Promise<ModuleResult> {
  return runStaticModule('STAT-004', 'Client-Trusted Payments & Webhooks', () => {
    const findings: Finding[] = [];

    for (const file of ctx.files) {
      if (!isCodeFile(file.relPath)) continue;
      if (!ctx.includeTests && isTestOrMockFile(file.relPath)) continue;
      if (isFrontendUiFile(file.relPath)) continue;

      // 1. Check webhook handlers for missing cryptographic signature verification
      for (let i = 0; i < file.lines.length; i++) {
        const line = file.lines[i];
        if (!WEBHOOK_ROUTE_REGEX.test(line)) continue;

        const lineNum = i + 1;
        const windowText = file.lines.slice(Math.max(0, i - 3), i + 30).join('\n');

        if (!SIGNATURE_VERIFY_REGEX.test(windowText)) {
          findings.push({
            id: 'STAT-004',
            title: 'Payment webhook handler lacks cryptographic signature verification',
            severity: 'CRITICAL',
            category: 'Validation & Payments',
            location: `${file.relPath}:${lineNum}`,
            evidence: line.trim().slice(0, 180),
            reproduction: `Inspect ${file.relPath}:${lineNum} and verify whether incoming webhook payloads are authenticated with HMAC / constructEvent.`,
            whyItMatters:
              'Without verifying the payment provider signature (e.g., Paystack HMAC-SHA512 or Stripe `constructEvent`), anyone can POST a forged `charge.success` or `checkout.session.completed` JSON payload and grant themselves paid products or credits for free.',
            howToFix:
              'Compute and compare the provider signature using the raw request body and a constant-time comparison (`crypto.timingSafeEqual` for Paystack HMAC-SHA512, or `stripe.webhooks.constructEvent` for Stripe) before processing any webhook event.\n\n' +
              `AI Fix Prompt: "Add strict webhook signature verification (HMAC-SHA512 with crypto.timingSafeEqual for Paystack or stripe.webhooks.constructEvent for Stripe) at ${file.relPath}:${lineNum}, returning 401 when the signature is missing or invalid."`,
          });
          break; // One webhook finding per file section
        }
      }

      // 2. Check for client-trusted price / amount in checkout or order handlers (deduped per handler window)
      if (CHECKOUT_CONTEXT_REGEX.test(file.content)) {
        let lastFlaggedLine = -30;
        for (let i = 0; i < file.lines.length; i++) {
          if (i - lastFlaggedLine < 20) continue;
          const line = file.lines[i];
          if (!CLIENT_PRICE_REGEX.test(line)) continue;

          const lineNum = i + 1;
          const handlerWindow = file.lines.slice(Math.max(0, i - 5), i + 25).join('\n');

          if (!DB_PRICE_LOOKUP_REGEX.test(handlerWindow)) {
            lastFlaggedLine = i;
            findings.push({
              id: 'STAT-004',
              title: 'Client-trusted price or amount read directly from request body',
              severity: 'CRITICAL',
              category: 'Validation & Payments',
              location: `${file.relPath}:${lineNum}`,
              evidence: line.trim().slice(0, 180),
              reproduction: `Inspect ${file.relPath}:${lineNum} — price/amount is taken from client input without a server-side catalog/DB lookup.`,
              whyItMatters:
                'Trusting `price` or `amount` from the client lets an attacker modify the HTTP request to pay $0.01 (or a negative amount) for an expensive product or subscription.',
              howToFix:
                'Accept only `productId`/`planId` and `quantity` from the client, then look up the authoritative unit price from your database or server-side catalog and calculate the total on the server.\n\n' +
                `AI Fix Prompt: "Stop trusting price/amount from req.body at ${file.relPath}:${lineNum}. Look up the item price from the server-side database/catalog and compute the total server-side."`,
            });
          }
        }
      }
    }

    return findings;
  });
}
