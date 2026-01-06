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
   🔒 PHASE 8.3: THREAT PROFILE COLLECTION
   ========================================================= */
const threatProfileRef = db.collection("qymailThreatProfiles");

/* =========================================================
   🔽 ADDITION START
   ATTACHMENT METADATA COLLECTION
   ========================================================= */
const attachmentRef = db.collection("qymailSessionAttachments");

/* 🔽 ADDITION: CLOUD STORAGE */
const bucket = admin.storage().bucket();
/* =========================================================
   🔼 ADDITION END
   ========================================================= */

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

  return { safe: errors / TEST_SAMPLE_SIZE < ERROR_THRESHOLD };
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
  if (!detection.safe) return { status: "ATTACK_DETECTED" };

  return { status: "KEY_ESTABLISHED", key: siftedKey.join("") };
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

  return { iv: iv.toString("hex"), ciphertext: encrypted };
}

/* =========================================================
   🔽 ADDITION: ATTACHMENT ENCRYPT / DECRYPT
   ========================================================= */
function encryptAttachment(buffer, aesKey) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv("aes-256-cbc", aesKey, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  return { iv: iv.toString("hex"), data: encrypted };
}

function decryptAttachment(buffer, ivHex, aesKey) {
  const decipher = crypto.createDecipheriv(
    "aes-256-cbc",
    aesKey,
    Buffer.from(ivHex, "hex")
  );
  return Buffer.concat([decipher.update(buffer), decipher.final()]);
}
/* ========================================================= */

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
   🔒 PHASE 8.3: PROFILE UPDATE HELPER
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

  profile.totalEvents++;
  profile.lastSeen = Date.now();

  if (threatLevel === "HIGH") profile.highThreatCount++;
  if (threatLevel === "MEDIUM") profile.mediumThreatCount++;
  if (threatLevel === "LOW") profile.lowThreatCount++;

  if (profile.highThreatCount >= 2) profile.currentRisk = "HIGH";
  else if (profile.mediumThreatCount >= 2) profile.currentRisk = "MEDIUM";
  else if (profile.lowThreatCount >= 2) profile.currentRisk = "LOW";

  await ref.set(profile);
}

// =======================
// PHASE 8: SEND SECURE MAIL
// =======================
exports.requestSecureSession = functions.https.onRequest(async (req, res) => {
  try {
    const token = req.headers.authorization?.split("Bearer ")[1];
    if (!token) return res.status(401).json({ error: "Login required" });

    const decoded = IS_EMULATOR
      ? { email: "emulator-user@qymail.local" }
      : await admin.auth().verifyIdToken(token);

    const { receiver, message, attachments } = req.body;
    if (!receiver || !message) {
      return res.status(400).json({ error: "Missing fields" });
    }

    const sessionId = "QY-" + Math.random().toString(36).slice(2);
    const qkd = runQKD();
    if (qkd.status !== "KEY_ESTABLISHED") return res.status(403).json(qkd);

    await db.collection("qymailSessions").doc(sessionId).set({
      key: qkd.key,
      receiver,
      createdAt: Date.now()
    });

    const aesKey = deriveAESKey(qkd.key);
    const encrypted = encryptEmail(message, aesKey);

    /* 🔽 ADDITION: STORE ENCRYPTED PDFs IN CLOUD STORAGE */
    if (Array.isArray(attachments)) {
      for (const file of attachments) {
        const buffer = Buffer.from(file.data, "base64");
        const enc = encryptAttachment(buffer, aesKey);

        const storagePath = `qymail/${sessionId}/${file.name}`;
        await bucket.file(storagePath).save(enc.data);

        await attachmentRef.add({
          sessionId,
          name: file.name,
          type: file.type,
          iv: enc.iv,
          storagePath
        });
      }
    }

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

    await updateThreatProfile(decoded.email, "NONE");

    return res.json({ status: "EMAIL_SENT_SECURELY", sessionId });

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

    const decoded = IS_EMULATOR
      ? { email: "emulator-user@qymail.local" }
      : await admin.auth().verifyIdToken(token);

    const { sessionId, iv, ciphertext } = req.body;
    if (!sessionId || !iv || !ciphertext) {
      return res.status(400).json({ error: "Missing payload" });
    }

    const doc = await db.collection("qymailSessions").doc(sessionId).get();
    if (!doc.exists) return res.status(404).json({ error: "Session not found" });

    const session = doc.data();
    if (!IS_EMULATOR && session.receiver !== decoded.email) {
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

    /* 🔽 ADDITION: RETRIEVE & DECRYPT PDFs */
    const snapshot = await attachmentRef.where("sessionId", "==", sessionId).get();
    const decryptedAttachments = [];

    for (const doc of snapshot.docs) {
      const a = doc.data();
      const [fileBuffer] = await bucket.file(a.storagePath).download();
      const decryptedFile = decryptAttachment(fileBuffer, a.iv, aesKey);

      decryptedAttachments.push({
        name: a.name,
        type: a.type,
        data: decryptedFile.toString("base64")
      });

      await bucket.file(a.storagePath).delete();
      await doc.ref.delete();
    }

    await db.collection("qymailSessions").doc(sessionId).delete();

    return res.json({
      status: "EMAIL_DECRYPTED",
      plaintext: decrypted,
      attachments: decryptedAttachments
    });

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
});
