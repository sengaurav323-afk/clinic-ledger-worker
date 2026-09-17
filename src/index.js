import { createRemoteJWKSet, jwtVerify, SignJWT, importPKCS8 } from "jose";

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

function timingSafeEqualHex(a, b) {
  if (a.length !== b.length) return false;
  let result = 0;
  for (let i = 0; i < a.length; i++) result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return result === 0;
}

async function verifyRazorpaySignature(rawBody, signatureHeader, env) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(env.RAZORPAY_WEBHOOK_SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sigBuffer = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(rawBody));
  const expectedHex = [...new Uint8Array(sigBuffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return timingSafeEqualHex(expectedHex, signatureHeader || "");
}

let cachedGoogleToken = null;
async function getGoogleAccessToken(env) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedGoogleToken && cachedGoogleToken.expiresAt > now + 30) return cachedGoogleToken.token;

  const privateKeyPem = env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n");
  const key = await importPKCS8(privateKeyPem, "RS256");

  const assertion = await new SignJWT({ scope: "https://www.googleapis.com/auth/datastore" })
    .setProtectedHeader({ alg: "RS256" })
    .setIssuer(env.FIREBASE_CLIENT_EMAIL)
    .setAudience("https://oauth2.googleapis.com/token")
    .setIssuedAt(now)
    .setExpirationTime(now + 3600)
    .sign(key);

  const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer&assertion=${encodeURIComponent(assertion)}`,
  });
  if (!tokenRes.ok) throw new Error("Failed to obtain Google access token");
  const tokenData = await tokenRes.json();
  cachedGoogleToken = { token: tokenData.access_token, expiresAt: now + tokenData.expires_in };
  return tokenData.access_token;
}

function firestoreBaseUrl(env) {
  return `https://firestore.googleapis.com/v1/projects/${env.FIREBASE_PROJECT_ID}/databases/(default)/documents`;
}

async function markPaymentProcessedOnce(paymentId, env, accessToken) {
  const res = await fetch(
    `${firestoreBaseUrl(env)}/processedPayments?documentId=${encodeURIComponent(paymentId)}`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
      body: JSON.stringify({ fields: { processedAt: { timestampValue: new Date().toISOString() } } }),
    }
  );
  if (res.status === 409) return false;
  if (!res.ok) throw new Error("Failed to record processed payment");
  return true;
}

async function updateUserSubscription(uid, plan, env, accessToken) {
  const startedAt = new Date().toISOString();

  const url =
    `${firestoreBaseUrl(env)}/users/${uid}` +
    `?updateMask.fieldPaths=subscriptionPlan&updateMask.fieldPaths=subscriptionStart`;

  const res = await fetch(url, {
    method: "PATCH",
    headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
    body: JSON.stringify({
      fields: {
        subscriptionPlan: { stringValue: plan },
        subscriptionStart: { stringValue: startedAt },
      },
    }),
  });
  if (!res.ok) throw new Error(`Firestore update failed: ${await res.text()}`);
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
    const errText = await orderRes.text();
    console.error("Razorpay order creation failed:", orderRes.status, errText);
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

async function handleWebhook(request, env) {
  const rawBody = await request.text();
  const signature = request.headers.get("X-Razorpay-Signature");

  if (!(await verifyRazorpaySignature(rawBody, signature, env))) {
    return json({ error: "Invalid signature" }, 400, env);
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    return json({ error: "Invalid payload" }, 400, env);
  }

  if (payload.event !== "payment.captured") {
    return json({ status: "ignored" }, 200, env);
  }

  const payment = payload.payload?.payment?.entity;
  const uid = payment?.notes?.firebaseUid;
  const plan = payment?.notes?.plan;
  const paymentId = payment?.id;
  if (!uid || !plan || !paymentId) {
    return json({ error: "Missing expected payment data" }, 400, env);
  }

  try {
    const accessToken = await getGoogleAccessToken(env);
    const isNew = await markPaymentProcessedOnce(paymentId, env, accessToken);
    if (!isNew) return json({ status: "already_processed" }, 200, env);
    await updateUserSubscription(uid, plan, env, accessToken);
  } catch (err) {
    console.error("Webhook processing failed:", err.message, err.stack);
    return json({ error: "Failed to process payment" }, 500, env);
  }

  return json({ status: "ok" }, 200, env);
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
    if (url.pathname === "/webhook" && request.method === "POST") {
      return handleWebhook(request, env);
    }
    return json({ error: "Not found" }, 404, env);
  },
};