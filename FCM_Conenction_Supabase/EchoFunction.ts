import { serve } from "https://deno.land/std@0.224.0/http/server.ts";
import { create, getNumericDate, Header, Payload } from "https://deno.land/x/djwt@v2.8/mod.ts";

// Decode your Base64 key
const encodedKey = Deno.env.get("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64");
if (!encodedKey) {
  console.error("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 is not set");
  throw new Error("FIREBASE_SERVICE_ACCOUNT_KEY_BASE64 is not set");
}
const decodedKey = new TextDecoder().decode(
  Uint8Array.from(atob(encodedKey), c => c.charCodeAt(0))
);
const firebaseConfig = JSON.parse(decodedKey);

function withCorsHeaders(resp) {
  resp.headers.set("Access-Control-Allow-Origin", "*");
  resp.headers.set("Access-Control-Allow-Methods", "POST, OPTIONS");
  // Add 'x-client-info' to the list of allowed headers
  resp.headers.set("Access-Control-Allow-Headers", "Content-Type, Authorization, apikey, x-client-info");
  return resp;
}


async function getAccessToken(serviceAccount) {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + 3600;
  const header: Header = { alg: "RS256", typ: "JWT" };
  const payload: Payload = {
    iss: serviceAccount.client_email,
    scope: "https://www.googleapis.com/auth/firebase.messaging",
    aud: "https://oauth2.googleapis.com/token",
    iat,
    exp,
  };
  const privateKeyPem = serviceAccount.private_key
    .replace(/-----BEGIN PRIVATE KEY-----/, '')
    .replace(/-----END PRIVATE KEY-----/, '')
    .replace(/\s/g, ''); // Remove newlines and spaces

  const binaryDer = Uint8Array.from(atob(privateKeyPem), c => c.charCodeAt(0));

  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    binaryDer,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["sign"]
  );

  const jwt = await create(header, payload, privateKey);

  const res = await fetch("https://oauth2.googleapis.com/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });
  if (!res.ok) throw new Error("Failed to get access token: " + (await res.text()));
  const { access_token } = await res.json();
  return access_token;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return withCorsHeaders(new Response("ok", { status: 200 }));
  }

  if (req.method !== "POST") {
    return withCorsHeaders(new Response("Method Not Allowed", { status: 405 }));
  }

  let tokens, title, body;
  try {
    const data = await req.json();
    tokens = data.tokens;
    title = data.title;
    body = data.body;
  } catch (e) {
    console.error("Invalid JSON:", e);
    return withCorsHeaders(new Response("Invalid JSON", { status: 400 }));
  }

  if (!tokens || !Array.isArray(tokens) || tokens.length === 0 || !title || !body) {
    console.error("Missing or invalid fields", { tokens, title, body });
    return withCorsHeaders(new Response("Missing or invalid fields", { status: 400 }));
  }

  try {
    const accessToken = await getAccessToken(firebaseConfig);
    const projectId = firebaseConfig.project_id;
    const url = `https://fcm.googleapis.com/v1/projects/${projectId}/messages:send`;
    const responses = [];
    for (const token of tokens) {
      const message = {
        message: {
          token,
          notification: { title, body },
        },
      };
      const res = await fetch(url, {
        method: "POST",
        headers: {
          "Authorization": `Bearer ${accessToken}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(message),
      });
      console.log("FCM Request URL:", url);
      console.log("FCM Request Headers:", {
        "Authorization": `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      });
      console.log("FCM Request Body:", JSON.stringify(message));

      const resBody = await res.text();
      console.log("FCM Response Status:", res.status);
      console.log("FCM Response Body:", resBody);
      responses.push({ status: res.status, body: resBody });
    }
    return withCorsHeaders(
      new Response(JSON.stringify({ fcmStatus: 200, fcmResponses: responses }), { status: 200 })
    );
    } catch (e) {
      console.error("FCM send error:", e);
      // Ensure e.stack is treated as a string, or provide a fallback
      const errorStack = e instanceof Error && e.stack ? e.stack : String(e);

      return withCorsHeaders(
        new Response(
          JSON.stringify({ fcmStatus: 500, fcmResponse: e.message, stack: errorStack }),
          { status: 500 }
        )
      );
    }


});
