// Direct-line message handler — Node.js 20.x Lambda
//
// Route:  POST /messages  (API Gateway HTTP API or Lambda Function URL)
// Flow:   validate → rate-limit by IP → store in DynamoDB → (optional) email via SES
//
// Environment variables:
//   TABLE_NAME      DynamoDB table (partition key: "pk" [S], sort key: "sk" [S])
//   ALLOWED_ORIGIN  e.g. https://mlabenski.github.io
//   NOTIFY_EMAIL    (optional) verified SES address to forward messages to
//   FROM_EMAIL      (optional) verified SES sender address

import { DynamoDBClient } from "@aws-sdk/client-dynamodb";
import { DynamoDBDocumentClient, PutCommand, QueryCommand } from "@aws-sdk/lib-dynamodb";
import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";
import { randomUUID } from "node:crypto";

const ddb = DynamoDBDocumentClient.from(new DynamoDBClient({}));
const ses = new SESv2Client({});

const LIMITS = { name: 80, contact: 120, message: 1200, ua: 160, page: 300 };
const RATE_WINDOW_MS = 60_000; // 1 message / minute / IP

const cors = (origin) => ({
  "Access-Control-Allow-Origin": origin,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
  "Content-Type": "application/json",
});

const resp = (status, body, origin) => ({
  statusCode: status,
  headers: cors(origin),
  body: JSON.stringify(body),
});

export const handler = async (event) => {
  const origin = process.env.ALLOWED_ORIGIN ?? "*";

  // CORS preflight
  const method = event.requestContext?.http?.method ?? event.httpMethod;
  if (method === "OPTIONS") return resp(204, {}, origin);
  if (method !== "POST") return resp(405, { error: "method not allowed" }, origin);

  // ── Parse & validate — schemas are contracts ──────────────────
  let data;
  try {
    data = JSON.parse(event.body ?? "{}");
  } catch {
    return resp(400, { error: "body must be valid JSON" }, origin);
  }

  const name = String(data.name ?? "").trim();
  const message = String(data.message ?? "").trim();
  const contact = data.contact == null ? null : String(data.contact).trim();
  const ua = String(data.ua ?? "").slice(0, LIMITS.ua);
  const page = String(data.page ?? "").slice(0, LIMITS.page);

  if (!name || !message)
    return resp(400, { error: "name and message are required" }, origin);
  if (name.length > LIMITS.name || message.length > LIMITS.message ||
      (contact && contact.length > LIMITS.contact))
    return resp(400, { error: "field exceeds maximum length" }, origin);

  // ── Rate limit: 1 message per IP per window ───────────────────
  const ip = event.requestContext?.http?.sourceIp ?? "unknown";
  const now = Date.now();
  const recent = await ddb.send(new QueryCommand({
    TableName: process.env.TABLE_NAME,
    KeyConditionExpression: "pk = :pk AND sk > :cutoff",
    ExpressionAttributeValues: {
      ":pk": `ip#${ip}`,
      ":cutoff": String(now - RATE_WINDOW_MS),
    },
    Limit: 1,
  }));
  if (recent.Count > 0)
    return resp(429, { error: "rate limited — one message per minute" }, origin);

  // ── Store ──────────────────────────────────────────────────────
  const id = randomUUID();
  const item = {
    pk: `ip#${ip}`,
    sk: String(now),
    messageId: id,
    name, contact, message, ua, page,
    createdAt: new Date(now).toISOString(),
    // TTL (epoch seconds): auto-expire raw records after 90 days
    expiresAt: Math.floor(now / 1000) + 90 * 24 * 3600,
  };
  await ddb.send(new PutCommand({ TableName: process.env.TABLE_NAME, Item: item }));

  // ── Optional: forward to inbox via SES ─────────────────────────
  if (process.env.NOTIFY_EMAIL && process.env.FROM_EMAIL) {
    try {
      await ses.send(new SendEmailCommand({
        FromEmailAddress: process.env.FROM_EMAIL,
        Destination: { ToAddresses: [process.env.NOTIFY_EMAIL] },
        Content: {
          Simple: {
            Subject: { Data: `Direct line — message from ${name}` },
            Body: {
              Text: {
                Data:
                  `From: ${name}\nReply-to: ${contact ?? "(none)"}\n` +
                  `Page: ${page}\nUA: ${ua}\nID: ${id}\n\n${message}`,
              },
            },
          },
        },
      }));
    } catch (e) {
      // Message is already stored; email failure shouldn't fail the request.
      console.error("SES forward failed:", e);
    }
  }

  return resp(200, { ok: true, resp: "00", messageId: id }, origin);
};
