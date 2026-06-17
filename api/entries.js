import { createClient } from "@supabase/supabase-js";
import crypto from "crypto";

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

function hashPasscode(passcode) {
  return crypto.createHash("sha256").update(String(passcode).trim()).digest("hex");
}

function isValidPasscode(passcode) {
  return typeof passcode === "string" && passcode.trim().length >= 4 && passcode.trim().length <= 64;
}

export default async function handler(req, res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");

  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }

  try {
    if (req.method === "GET") {
      const passcode = req.query.passcode;
      if (!isValidPasscode(passcode)) {
        return res.status(400).json({ error: "Invalid passcode" });
      }
      const passcodeHash = hashPasscode(passcode);

      const { data, error } = await supabase
        .from("journals")
        .select("entries")
        .eq("passcode_hash", passcodeHash)
        .maybeSingle();

      if (error) {
        console.error(error);
        return res.status(500).json({ error: "Server error" });
      }

      return res.status(200).json({ entries: data ? data.entries : {} });
    }

    if (req.method === "POST") {
      const { passcode, entries } = req.body || {};
      if (!isValidPasscode(passcode)) {
        return res.status(400).json({ error: "Invalid passcode" });
      }
      if (!entries || typeof entries !== "object") {
        return res.status(400).json({ error: "Invalid entries payload" });
      }
      const passcodeHash = hashPasscode(passcode);

      const { error } = await supabase
        .from("journals")
        .upsert(
          {
            passcode_hash: passcodeHash,
            entries,
            updated_at: new Date().toISOString(),
          },
          { onConflict: "passcode_hash" }
        );

      if (error) {
        console.error(error);
        return res.status(500).json({ error: "Server error" });
      }

      return res.status(200).json({ ok: true });
    }

    return res.status(405).json({ error: "Method not allowed" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "Server error" });
  }
}
