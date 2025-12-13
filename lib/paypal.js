// lib/paypal.js
const axios = require("axios");

const PAYPAL_API = process.env.PAYPAL_API;
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;

if (!PAYPAL_API || !PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
  throw new Error("❌ Missing PayPal LIVE configuration");
}

console.log("💳 PayPal initialized in LIVE mode");

// =============================
// AUTH
// =============================
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

// =============================
// CREATE SUBSCRIPTION
// =============================
async function createSubscription({ planId, userId }) {
  const token = await getPayPalAccessToken();

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
      },
      timeout: 15000,
    }
  );

  return res.data;
}

// =============================
// CANCEL SUBSCRIPTION
// =============================
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
};
