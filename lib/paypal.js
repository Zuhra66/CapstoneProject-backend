// lib/paypal.js
const axios = require("axios");

// ======================================================
// ENV MODE
// ======================================================
const isLive = process.env.PAYPAL_MODE === "live";

const PAYPAL_API = isLive
  ? "https://api-m.paypal.com"
  : "https://api-m.sandbox.paypal.com";

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;

if (!PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
  throw new Error("❌ Missing PayPal credentials");
}

console.log(`💳 PayPal initialized in ${isLive ? "LIVE" : "SANDBOX"} mode`);

// ======================================================
// AUTH
// ======================================================
async function getPayPalAccessToken() {
  const res = await axios.post(
    `${PAYPAL_API}/v1/oauth2/token`,
    "grant_type=client_credentials",
    {
      auth: {
        username: PAYPAL_CLIENT_ID,
        password: PAYPAL_CLIENT_SECRET,
      },
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      timeout: 15000,
    }
  );

  return res.data.access_token;
}

// ======================================================
// VERIFY PAYPAL WEBHOOK SIGNATURE
// ======================================================
async function verifyPaypalWebhook(req) {
  const token = await getPayPalAccessToken();

  const res = await axios.post(
    `${PAYPAL_API}/v1/notifications/verify-webhook-signature`,
    {
      transmission_id: req.headers["paypal-transmission-id"],
      transmission_time: req.headers["paypal-transmission-time"],
      cert_url: req.headers["paypal-cert-url"],
      auth_algo: req.headers["paypal-auth-algo"],
      transmission_sig: req.headers["paypal-transmission-sig"],
      webhook_id: process.env.PAYPAL_WEBHOOK_ID,
      webhook_event: req.body,
    },
    {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      timeout: 15000,
    }
  );

  return res.data.verification_status === "SUCCESS";
}

// ======================================================
// CREATE SUBSCRIPTION
// ======================================================
const requestId = `sub-${userId}`;

const res = await axios.post(
  `${PAYPAL_API}/v1/billing/subscriptions`,
  {
    plan_id: planId,
    custom_id: String(userId),
    application_context: {
      brand_name: "EmpowerMEd Wellness",
      user_action: "SUBSCRIBE_NOW",
      return_url: `${process.env.FRONTEND_URL}/membership/success`,
      cancel_url: `${process.env.FRONTEND_URL}/membership/cancel`,
    },
  },
  {
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      "PayPal-Request-Id": requestId,
    },
    timeout: 15000,
  }
);

// ======================================================
// CANCEL SUBSCRIPTION
// ======================================================
async function cancelPaypalSubscription(subscriptionId) {
  if (!subscriptionId) {
    throw new Error("Missing PayPal subscription ID");
  }

  const token = await getPayPalAccessToken();

  await axios.post(
    `${PAYPAL_API}/v1/billing/subscriptions/${subscriptionId}/cancel`,
    { reason: "Subscription cancelled by system" },
    {
      headers: {
        Authorization: `Bearer ${token}`,
      },
      timeout: 15000,
    }
  );
}

module.exports = {
  createSubscription,
  cancelPaypalSubscription,
  verifyPaypalWebhook,
};
