// Stripe webhook — one endpoint, handles every real payment on the site
// (preorders and Fund the Work donations) and bumps the right public
// counter. Nothing on this page is a hand-typed or fabricated number;
// every count here only moves when a real, verified Stripe payment lands.
//
// How it tells the four Payment Links apart:
//   Each Payment Link has a "product" metadata tag set in Stripe (see
//   setup steps below). That tag rides along on the Checkout Session
//   Stripe sends here, so we don't have to guess based on price --
//   important since the preorder prices ($45 / $90) can collide with a
//   donation amount someone chooses in $5 increments.
//
// Expected metadata values, one per Payment Link:
//   preorder-12x18      -> bumps the preorder counter
//   preorder-18x24      -> bumps the preorder counter
//   donation-recurring  -> bumps donor count + adds to the dollar total
//   donation-onetime    -> bumps donor count + adds to the dollar total
//
// One-time setup required in Stripe + Vercel (can't be done from here):
//   1. For each of the 4 Payment Links: Stripe Dashboard -> Payment
//      Links -> open the link -> Edit -> Advanced/Additional options ->
//      Metadata -> add key "product" with the matching value above.
//   2. Stripe Dashboard -> Developers -> Webhooks -> Add endpoint
//      URL: https://hpntk.co/api/stripe-webhook
//      Event to send: checkout.session.completed
//   3. Stripe shows a signing secret (starts with "whsec_") once the
//      endpoint is created -- copy it.
//   4. Vercel Dashboard -> hpntk.co project -> Settings -> Environment
//      Variables -> add STRIPE_WEBHOOK_SECRET with that value, then
//      redeploy so the function picks it up.

import crypto from "node:crypto";

export const config = { runtime: "nodejs" };

const COUNTER_API = "https://countapi.mileshilliard.com/api/v1/";
const PREORDER_COUNTER_KEY = "hpntk-co-a-beautiful-preorder-2026";
const DONOR_COUNT_KEY = "hpntk-co-donor-count-2026";
const DONATION_TOTAL_KEY = "hpntk-co-donation-total-cents-2026";
const SIGNATURE_TOLERANCE_SECONDS = 300; // reject events older than 5 min

const PREORDER_PRODUCTS = ["preorder-12x18", "preorder-18x24"];
const DONATION_PRODUCTS = ["donation-recurring", "donation-onetime"];

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

async function hitCounter(key) {
  await fetch(COUNTER_API + "hit/" + key);
}

async function addToDollarTotal(key, addCents) {
  // The free counting service only supports "+1" or "set to this exact
  // value" -- there's no atomic "add N". So this reads the current
  // total, adds the new donation on top, and writes it back. If two
  // donations landed in the exact same instant this read-then-write
  // could clobber one of them -- an acceptable, low-probability tradeoff
  // for this site's volume, not something worth a real database over.
  var current = 0;
  try {
    var getRes = await fetch(COUNTER_API + "get/" + key);
    if (getRes.ok) {
      var data = await getRes.json();
      current = Number(data.value) || 0;
    }
  } catch (e) {
    current = 0;
  }
  var next = current + addCents;
  await fetch(COUNTER_API + "set/" + key + "?value=" + next);
}

export async function POST(request) {
  const secret = process.env.STRIPE_WEBHOOK_SECRET;
  const rawBody = await request.text();
  const signature = request.headers.get("stripe-signature");

  if (!secret) {
    return new Response("STRIPE_WEBHOOK_SECRET is not set in Vercel env vars", {
      status: 500,
    });
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
    const product = session && session.metadata && session.metadata.product;
    const amount = session && session.amount_total;

    try {
      if (PREORDER_PRODUCTS.indexOf(product) !== -1) {
        await hitCounter(PREORDER_COUNTER_KEY);
      } else if (DONATION_PRODUCTS.indexOf(product) !== -1) {
        await hitCounter(DONOR_COUNT_KEY);
        if (typeof amount === "number") {
          await addToDollarTotal(DONATION_TOTAL_KEY, amount);
        }
      }
      // No recognized "product" metadata -- most likely a Payment Link
      // that hasn't been tagged yet. Deliberately ignored rather than
      // guessed at, so nothing gets miscounted.
    } catch (e) {
      // Swallow -- still return 200 below so Stripe doesn't retry-storm
      // us over a display-only number.
    }
  }

  return new Response("ok", { status: 200 });
}
