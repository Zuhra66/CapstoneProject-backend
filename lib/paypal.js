//paypal.js

const axios = require("axios");

// ----------------------------
// AUTH
// ----------------------------
async function getPayPalAccessToken() {
  const res = await axios.post(
    `${process.env.PAYPAL_API}/v1/oauth2/token`,
    "grant_type=client_credentials",
    {
      auth: {
        username: process.env.PAYPAL_CLIENT_ID,
        password: process.env.PAYPAL_CLIENT_SECRET,
      },
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
    }
  );

  return res.data.access_token;
}

// ----------------------------
// CREATE SUBSCRIPTION (USER FLOW)
// ----------------------------
async function createSubscription({ planId, userId }) {
  const token = await getPayPalAccessToken();

  const res = await axios.post(
    `${process.env.PAYPAL_API}/v1/billing/subscriptions`,
    {
      plan_id: planId,
      custom_id: userId, // 🔑 internal user mapping
      application_context: {
        brand_name: "EmpowerMEd",
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
    }
  );

  return res.data;
}

// ----------------------------
// CANCEL SUBSCRIPTION (ADMIN / USER)
// ----------------------------
async function cancelPaypalSubscription(subscriptionId) {
  const token = await getPayPalAccessToken();

  await axios.post(
    `${process.env.PAYPAL_API}/v1/billing/subscriptions/${subscriptionId}/cancel`,
    {
      reason: "Subscription cancelled by system",
    },
    {
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    }
  );
}

// ----------------------------
// EXPORTS
// ----------------------------
module.exports = {
  createSubscription,
  cancelPaypalSubscription,
};
