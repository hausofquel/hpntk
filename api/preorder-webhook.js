// Preorder webhook — listens for real Stripe payments and bumps the
// public preorder counter shown on the site. This is the "auto" half of
// the preorder tracker: nobody edits a number by hand anymore, this file
// verifies the payment actually happened and increments for real.
//
// How it works:
//   1. Stripe calls this URL every time a checkout completes, for every
//      Payment Link on the account (not just the preorder ones).
//   2. We verify the request really came from Stripe using the signing
//      secret (STRIPE_PREORDER_WEBHOOK_SECRET) -- without this check,
//      anyone who found this URL could POST a fake "payment completed"
//      event and inflate the counter.
//   3. We only count it if the amount matches a known preorder price, so
//      a Fund the Work investment doesn't get counted as a preorder.
//
// One-time setup required in Stripe + Vercel (can't be done from here):
//   1. Stripe Dashboard -> Developers -> Webhooks -> Add endpoint
//      URL: https://hpntk.co/api/preorder-webhook
//      Event to send: checkout.session.completed
//   2. Stripe shows a signing secret (starts with "whsec_") once the
//      endpoint is created -- copy it.
//   3. Vercel Dashboard -> hpntk.co project -> Settings -> Environment
//      Variables -> add STRIPE_PREORDER_WEBHOOK_SECRET with that value.
//      Redeploy so the function picks it up.
//
// If the $45 / $90 preorder prices ever change, update PREORDER_AMOUNTS
// below (values are in cents) or this stops counting new preorders.

import crypto from "node:crypto";

export const config = { runtime: "nodejs" };

const COUNTER_API = "https://countapi.mileshilliard.com/api/v1/";
const COUNTER_KEY = "hpntk-co-a-beautiful-preorder-2026";
const PREORDER_AMOUNTS = [9000, 4500]; // $90 (18"x24"), $45 (12"x18"), in cents
const SIGNATURE_TOLERANCE_SECONDS = 300; // reject events older than 5 min

function verifyStripeSignature(rawBody, signatureHeader, secret) {
  if (!signatureHeader || !secret) return false;

  var parts = signatureHeader.split(",").reduce(function (acc, part) {
    var pair = part.split("=");
    acc[pair[0]] = pair[1];
    return acc;
  }, {});

  var timestamp = parts.t;
  var v1 = parts.v1;
  if (!timestamp || !v1) return false;

  var age = Math.abs(Date.now() / 1000 - Number(timestamp));
  if (age > SIGNATURE_TOLERANCE_SECONDS) return false;

  var signedPayload = timestamp + "." + rawBody;
  var expected = crypto
    .createHmac("sha256", secret)
    .update(signedPayload, "utf8")
    .digest("hex");

  try {
    return crypto.timingSafeEqual(
      Buffer.from(expected, "utf8"),
      Buffer.from(v1, "utf8"),
    );
  } catch (e) {
    // Buffer length mismatch (e.g. malformed header) throws -- treat as
    // a failed verification rather than crashing.
    return false;
  }
}

export async function POST(request) {
  const secret = process.env.STRIPE_PREORDER_WEBHOOK_SECRET;
  const rawBody = await request.text();
  const signature = request.headers.get("stripe-signature");

  if (!secret) {
    return new Response(
      "STRIPE_PREORDER_WEBHOOK_SECRET is not set in Vercel env vars",
      { status: 500 },
    );
  }

  if (!verifyStripeSignature(rawBody, signature, secret)) {
    return new Response("Signature verification failed", { status: 400 });
  }

  let event;
  try {
    event = JSON.parse(rawBody);
  } catch (e) {
    return new Response("Invalid JSON payload", { status: 400 });
  }

  if (event.type === "checkout.session.completed") {
    const session = event.data && event.data.object;
    const amount = session && session.amount_total;

    if (PREORDER_AMOUNTS.indexOf(amount) !== -1) {
      try {
        await fetch(COUNTER_API + "hit/" + COUNTER_KEY);
      } catch (e) {
        // If the counter service hiccups, still return 200 below so
        // Stripe doesn't retry-storm us over a display-only number.
      }
    }
  }

  return new Response("ok", { status: 200 });
}
