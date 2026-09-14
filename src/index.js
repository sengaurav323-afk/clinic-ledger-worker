import { createRemoteJWKSet, jwtVerify } from "jose";

const PLAN_PRICES = {
  monthly: { amountPaise: 9900, label: "Monthly" },
  yearly: { amountPaise: 99900, label: "Yearly" },
};

function corsHeaders(env) {
  return {
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
}

function json(data, status, env) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(env) },
  });
}

let cachedJWKS = null;
async function getFirebaseJWKS() {
  if (!cachedJWKS) {
    cachedJWKS = createRemoteJWKSet(
      new URL("https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com")
    );
  }
  return cachedJWKS;
}

async function verifyFirebaseIdToken(idToken, env) {
  const { payload } = await jwtVerify(idToken, await getFirebaseJWKS(), {
    issuer: `https://securetoken.google.com/${env.FIREBASE_PROJECT_ID}`,
    audience: env.FIREBASE_PROJECT_ID,
  });
  if (!payload.sub) throw new Error("Token missing subject");
  return payload.sub;
}

async function handleCreateOrder(request, env) {
  const authHeader = request.headers.get("Authorization") || "";
  const idToken = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;
  if (!idToken) return json({ error: "Missing authentication" }, 401, env);

  let uid;
  try {
    uid = await verifyFirebaseIdToken(idToken, env);
  } catch (err) {
    return json({ error: "Invalid or expired session — please sign in again" }, 401, env);
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "Invalid request" }, 400, env);
  }

  const plan = body.plan;
  if (plan !== "monthly" && plan !== "yearly") {
    return json({ error: "Invalid plan" }, 400, env);
  }

  const { amountPaise, label } = PLAN_PRICES[plan];

  const razorpayAuth = "Basic " + btoa(`${env.RAZORPAY_KEY_ID}:${env.RAZORPAY_KEY_SECRET}`);
  const orderRes = await fetch("https://api.razorpay.com/v1/orders", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: razorpayAuth },
    body: JSON.stringify({
      amount: amountPaise,
      currency: "INR",
      receipt: `sub_${uid}_${Date.now()}`,
      notes: { firebaseUid: uid, plan },
    }),
  });

  if (!orderRes.ok) {
    return json({ error: "Could not create payment order — please try again" }, 502, env);
  }
  const order = await orderRes.json();

  return json(
    {
      orderId: order.id,
      amount: amountPaise,
      currency: "INR",
      keyId: env.RAZORPAY_KEY_ID,
      planLabel: label,
    },
    200,
    env
  );
}

export default {
  async fetch(request, env) {
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders(env) });
    }
    const url = new URL(request.url);
    if (url.pathname === "/create-order" && request.method === "POST") {
      return handleCreateOrder(request, env);
    }
    return json({ error: "Not found" }, 404, env);
  },
};
