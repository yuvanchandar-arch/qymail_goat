const functions = require("firebase-functions");
const admin = require("firebase-admin");
const crypto = require("crypto");
const nodemailer = require("nodemailer");

admin.initializeApp();

// =======================
// SESSION KEY STORE
// =======================
const db = admin.firestore();

/* =========================================================
   🔧 ONLY ADDITION (1 LINE)
   Detect if running in Firebase Functions Emulator
   ========================================================= */
const IS_EMULATOR = process.env.FUNCTIONS_EMULATOR === "true";

/* =========================================================
   🔒 PHASE 8.1: THREAT LOG COLLECTION
   ========================================================= */
const threatLogRef = db.collection("qymailThreatLogs");

/* =========================================================
   🔒 PHASE 8.3: THREAT PROFILE COLLECTION (NEW)
   ========================================================= */
const threatProfileRef = db.collection("qymailThreatProfiles");

// =======================
// PHASE 3: QKD PARAMETERS
// =======================
const TOTAL_BITS = 64;
const TEST_SAMPLE_SIZE = 16;
const ERROR_THRESHOLD = 0.25;

// =======================
// PHASE 3: QKD UTILITIES
// =======================
function randomBit() {
  return Math.random() < 0.5 ? 0 : 1;
}

function randomBasis() {
  return Math.random() < 0.5 ? "+" : "x";
}

// =======================
// PHASE 3: SENDER
// =======================
function generateSenderData() {
  const bits = [];
  const bases = [];

  for (let i = 0; i < TOTAL_BITS; i++) {
    bits.push(randomBit());
    bases.push(randomBasis());
  }

  return { bits, bases };
}

// =======================
// PHASE 3: RECEIVER
// =======================
function measureReceiver(senderBits, senderBases) {
  const receiverBases = [];
  const measuredBits = [];

  for (let i = 0; i < TOTAL_BITS; i++) {
    const basis = randomBasis();
    receiverBases.push(basis);

    if (basis === senderBases[i]) {
      measuredBits.push(senderBits[i]);
    } else {
      measuredBits.push(randomBit());
    }
  }

  return { receiverBases, measuredBits };
}

// =======================
// PHASE 3: KEY SIFTING
// =======================
function siftKey(senderBits, senderBases, receiverBases, receiverBits) {
  const siftedKey = [];

  for (let i = 0; i < TOTAL_BITS; i++) {
    if (senderBases[i] === receiverBases[i]) {
      siftedKey.push(receiverBits[i]);
    }
  }

  return siftedKey;
}

// =======================
// PHASE 3: EAVESDROPPING DETECTION
// =======================
function detectEavesdropping(siftedKey) {
  if (siftedKey.length < TEST_SAMPLE_SIZE) {
    return { safe: false };
  }

  let errors = 0;
  for (let i = 0; i < TEST_SAMPLE_SIZE; i++) {
    if (Math.random() < 0.1) errors++;
  }

  return {
    safe: errors / TEST_SAMPLE_SIZE < ERROR_THRESHOLD
  };
}

// =======================
// PHASE 3: QKD CONTROLLER
// =======================
function runQKD() {
  const sender = generateSenderData();
  const receiver = measureReceiver(sender.bits, sender.bases);

  const siftedKey = siftKey(
    sender.bits,
    sender.bases,
    receiver.receiverBases,
    receiver.measuredBits
  );

  const detection = detectEavesdropping(siftedKey);

  if (!detection.safe) {
    return { status: "ATTACK_DETECTED" };
  }

  return {
    status: "KEY_ESTABLISHED",
    key: siftedKey.join("")
  };
}

// =======================
// PHASE 5: ENCRYPTION
// =======================
function deriveAESKey(qkdKey) {
  return crypto.createHash("sha256").update(qkdKey).digest();
}

function encryptEmail(message, aesKey) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);

  let encrypted = cipher.update(message, "utf8", "hex");
  encrypted += cipher.final("hex");

  return {
    iv: iv.toString("hex"),
    ciphertext: encrypted
  };
}

// =======================
// PHASE 6: SMTP CONFIG
// =======================
const SMTP_USER = "murthythiru2926@gmail.com";

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: SMTP_USER,
    pass: "gtacdcamfkgeymoh"
  }
});

/* =========================================================
   🔒 PHASE 8.3: PROFILE UPDATE HELPER (NEW, SAFE)
   ========================================================= */
async function updateThreatProfile(actor, threatLevel) {
  const ref = threatProfileRef.doc(actor);
  const snap = await ref.get();

  let profile = snap.exists ? snap.data() : {
    actor,
    totalEvents: 0,
    highThreatCount: 0,
    mediumThreatCount: 0,
    lowThreatCount: 0,
    currentRisk: "NONE",
    lastSeen: 0
  };

  profile.totalEvents += 1;
  profile.lastSeen = Date.now();

  if (threatLevel === "HIGH") profile.highThreatCount += 1;
  if (threatLevel === "MEDIUM") profile.mediumThreatCount += 1;
  if (threatLevel === "LOW") profile.lowThreatCount += 1;

  // 🔒 Risk calculation (rule-based)
  if (profile.highThreatCount >= 2) {
    profile.currentRisk = "HIGH";
  } else if (profile.mediumThreatCount >= 2) {
    profile.currentRisk = "MEDIUM";
  } else if (profile.lowThreatCount >= 2) {
    profile.currentRisk = "LOW";
  } else {
    profile.currentRisk = "NONE";
  }

  await ref.set(profile);
}

// =======================
// PHASE 8: SEND SECURE MAIL
// =======================
exports.requestSecureSession = functions.https.onRequest(async (req, res) => {
  try {
    const token = req.headers.authorization?.split("Bearer ")[1];
    if (!token) return res.status(401).json({ error: "Login required" });

    let decoded;
    if (IS_EMULATOR) {
      decoded = { email: "emulator-user@qymail.local" };
    } else {
      decoded = await admin.auth().verifyIdToken(token);
    }

    const { receiver, message } = req.body;
    if (!receiver || !message) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const sessionId = "QY-" + Math.random().toString(36).slice(2);

    const qkd = runQKD();
    if (qkd.status !== "KEY_ESTABLISHED") {
      return res.status(403).json(qkd);
    }

    await db.collection("qymailSessions").doc(sessionId).set({
      key: qkd.key,
      receiver,
      createdAt: Date.now()
    });

    const aesKey = deriveAESKey(qkd.key);
    const encrypted = encryptEmail(message, aesKey);

    await transporter.sendMail({
      from: `"QYMail Secure" <${SMTP_USER}>`,
      to: receiver,
      subject: "🔐 Quantum Secure Email (QYMail)",
      text: `Session ID: ${sessionId}\nIV: ${encrypted.iv}\nCiphertext: ${encrypted.ciphertext}`
    });

    await threatLogRef.add({
      eventType: "SEND",
      sessionId,
      sender: decoded.email,
      receiver,
      timestamp: Date.now(),
      environment: IS_EMULATOR ? "EMULATOR" : "PRODUCTION",
      threatLevel: "NONE",
      ruleTriggered: "NORMAL_OPERATION"
    });

    // 🔒 PHASE 8.3 PROFILE UPDATE (SAFE)
    await updateThreatProfile(decoded.email, "NONE");

    return res.json({
      status: "EMAIL_SENT_SECURELY",
      sessionId,
      sender: decoded.email,
      receiver
    });

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});

// =======================
// PHASE 8: DECRYPT SECURE MAIL
// =======================
exports.decryptSecureEmail = functions.https.onRequest(async (req, res) => {
  try {
    const token = req.headers.authorization?.split("Bearer ")[1];
    if (!token) return res.status(401).json({ error: "Login required" });

    let decoded;
    if (IS_EMULATOR) {
      decoded = { email: "emulator-user@qymail.local" };
    } else {
      decoded = await admin.auth().verifyIdToken(token);
    }

    const { sessionId, iv, ciphertext } = req.body;

    if (!sessionId || !iv || !ciphertext) {
      await threatLogRef.add({
        eventType: "DECRYPT_ATTEMPT",
        sessionId: sessionId || "UNKNOWN",
        actor: decoded.email,
        result: "MISSING_PAYLOAD",
        timestamp: Date.now(),
        environment: IS_EMULATOR ? "EMULATOR" : "PRODUCTION",
        threatLevel: "LOW",
        ruleTriggered: "MALFORMED_REQUEST"
      });

      await updateThreatProfile(decoded.email, "LOW");
      return res.status(400).json({ error: "Missing payload" });
    }

    const doc = await db.collection("qymailSessions").doc(sessionId).get();
    if (!doc.exists) {
      await threatLogRef.add({
        eventType: "DECRYPT_ATTEMPT",
        sessionId,
        actor: decoded.email,
        result: "SESSION_NOT_FOUND",
        timestamp: Date.now(),
        environment: IS_EMULATOR ? "EMULATOR" : "PRODUCTION",
        threatLevel: "MEDIUM",
        ruleTriggered: "INVALID_SESSION"
      });

      await updateThreatProfile(decoded.email, "MEDIUM");
      return res.status(404).json({ error: "Session not found or expired" });
    }

    const session = doc.data();
    if (!IS_EMULATOR && session.receiver !== decoded.email) {
      await threatLogRef.add({
        eventType: "DECRYPT_ATTEMPT",
        sessionId,
        actor: decoded.email,
        result: "UNAUTHORIZED_RECEIVER",
        timestamp: Date.now(),
        environment: IS_EMULATOR ? "EMULATOR" : "PRODUCTION",
        threatLevel: "HIGH",
        ruleTriggered: "RECEIVER_MISMATCH"
      });

      await updateThreatProfile(decoded.email, "HIGH");
      return res.status(403).json({ error: "Unauthorized receiver" });
    }

    const aesKey = deriveAESKey(session.key);
    const decipher = crypto.createDecipheriv(
      "aes-256-cbc",
      aesKey,
      Buffer.from(iv, "hex")
    );

    let decrypted = decipher.update(ciphertext, "hex", "utf8");
    decrypted += decipher.final("utf8");

    await db.collection("qymailSessions").doc(sessionId).delete();

    await threatLogRef.add({
      eventType: "DECRYPT_ATTEMPT",
      sessionId,
      actor: decoded.email,
      result: "SUCCESS",
      timestamp: Date.now(),
      environment: IS_EMULATOR ? "EMULATOR" : "PRODUCTION",
      threatLevel: "NONE",
      ruleTriggered: "NORMAL_OPERATION"
    });

    await updateThreatProfile(decoded.email, "NONE");

    return res.json({
      status: "EMAIL_DECRYPTED",
      plaintext: decrypted
    });

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});
