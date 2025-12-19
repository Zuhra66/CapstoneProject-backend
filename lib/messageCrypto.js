// lib/messageCrypto.js
const crypto = require("crypto");

const ALGO = "aes-256-gcm";

// 32 bytes = 64 hex chars
const KEY = Buffer.from(process.env.MESSAGE_ENCRYPTION_KEY, "hex");

if (!process.env.MESSAGE_ENCRYPTION_KEY || KEY.length !== 32) {
  throw new Error("MESSAGE_ENCRYPTION_KEY must be a 32-byte hex string");
}

function encryptMessage(plaintext) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGO, KEY, iv);

  const encrypted = Buffer.concat([
    cipher.update(plaintext, "utf8"),
    cipher.final(),
  ]);

  return {
    ciphertext: encrypted.toString("base64"), // TEXT
    iv,                                       // BYTEA
    auth_tag: cipher.getAuthTag(),            // BYTEA
  };
}

/**
 * Decrypt message read from DB
 */
function decryptMessage({ ciphertext, iv, auth_tag }) {
  const decipher = crypto.createDecipheriv(ALGO, KEY, iv);
  decipher.setAuthTag(auth_tag);

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(ciphertext, "base64")),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}

module.exports = {
  encryptMessage,
  decryptMessage,
};
