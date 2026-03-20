// ============================
// image-locker.js
// Copyright 2026 Team Sonahiru
// ============================

/* image-locker.js
   Node.js / Browser 両対応の単一ファイル版
   方式: [ダミー画像] + [暗号化ペイロード] + [フッター]
*/

const ImageLocker = (() => {
  const cryptoImpl =
    globalThis.crypto ??
    (typeof require === "function" ? require("node:crypto").webcrypto : null);

  const TE =
    globalThis.TextEncoder ??
    (typeof require === "function" ? require("node:util").TextEncoder : null);
  const TD =
    globalThis.TextDecoder ??
    (typeof require === "function" ? require("node:util").TextDecoder : null);

  if (!cryptoImpl?.subtle || !cryptoImpl.getRandomValues || !TE || !TD) {
    throw new Error("Web Crypto / TextEncoder が使えません。Node.js 18+ か対応ブラウザで使ってください。");
  }

  const te = new TE();
  const td = new TD();

  const MAGIC_PAYLOAD = te.encode("IMGENC01"); // 8 bytes
  const MAGIC_FOOTER = te.encode("IMGFTR01");   // 8 bytes
  const VERSION = 1;

  const SALT_LEN = 16;
  const IV_LEN = 12;
  const FOOTER_LEN = MAGIC_FOOTER.length + 4; // magic + payloadLength(u32be)

  function concatBytes(...parts) {
    const total = parts.reduce((sum, p) => sum + p.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const p of parts) {
      out.set(p, offset);
      offset += p.length;
    }
    return out;
  }

  function u32be(n) {
    const out = new Uint8Array(4);
    const dv = new DataView(out.buffer);
    dv.setUint32(0, n >>> 0, false);
    return out;
  }

  function readU32BE(bytes, offset) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    return dv.getUint32(offset, false);
  }

  function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function toU8Sync(input) {
    if (input instanceof Uint8Array) return new Uint8Array(input);
    if (typeof Buffer !== "undefined" && Buffer.isBuffer?.(input)) {
      return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    }
    if (ArrayBuffer.isView(input)) {
      return new Uint8Array(input.buffer, input.byteOffset, input.byteLength);
    }
    if (input instanceof ArrayBuffer) return new Uint8Array(input);
    throw new TypeError("Uint8Array / ArrayBuffer / Buffer / Blob / File を渡してください");
  }

  async function toBytes(input) {
    if (input == null) throw new TypeError("入力が空です");

    if (typeof Blob !== "undefined" && input instanceof Blob) {
      return new Uint8Array(await input.arrayBuffer());
    }
    return toU8Sync(input);
  }

  function bytesToBlob(bytes, mimeType = "application/octet-stream") {
    return new Blob([bytes], { type: mimeType });
  }

  async function deriveKey(password, salt, iterations) {
    const baseKey = await cryptoImpl.subtle.importKey(
      "raw",
      te.encode(String(password)),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    return cryptoImpl.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256",
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptImage({
    inputImage,
    dummyImage,
    password,
    mimeType,
    dummyMimeType,
    iterations = 210000,
  }) {
    if (!password) throw new Error("password は必須です");
    if (!inputImage) throw new Error("inputImage は必須です");
    if (!dummyImage) throw new Error("dummyImage は必須です");

    const realBytes = await toBytes(inputImage);
    const fakeBytes = await toBytes(dummyImage);

    const realMime =
      mimeType ||
      inputImage?.type ||
      "application/octet-stream";

    const fakeMime =
      dummyMimeType ||
      dummyImage?.type ||
      realMime ||
      "image/png";

    const mimeBytes = te.encode(realMime);
    if (mimeBytes.length > 255) {
      throw new Error("mimeType が長すぎます");
    }

    const salt = cryptoImpl.getRandomValues(new Uint8Array(SALT_LEN));
    const iv = cryptoImpl.getRandomValues(new Uint8Array(IV_LEN));
    const key = await deriveKey(password, salt, iterations);

    const encrypted = new Uint8Array(
      await cryptoImpl.subtle.encrypt(
        { name: "AES-GCM", iv },
        key,
        realBytes
      )
    );

    const payload = concatBytes(
      MAGIC_PAYLOAD,
      new Uint8Array([VERSION]),
      new Uint8Array([mimeBytes.length]),
      mimeBytes,
      u32be(iterations),
      salt,
      iv,
      encrypted
    );

    const footer = concatBytes(
      MAGIC_FOOTER,
      u32be(payload.length)
    );

    const combinedBytes = concatBytes(fakeBytes, payload, footer);

    return {
      combinedBytes,
      combinedBlob: bytesToBlob(combinedBytes, fakeMime),
      mimeType: realMime,
      dummyMimeType: fakeMime,
      iterations,
    };
  }

  async function decryptImage({ combinedImage, password }) {
    if (!password) throw new Error("password は必須です");
    if (!combinedImage) throw new Error("combinedImage は必須です");

    const bytes = await toBytes(combinedImage);

    if (bytes.length < FOOTER_LEN) {
      throw new Error("データが短すぎます");
    }

    const footerStart = bytes.length - FOOTER_LEN;
    const footerMagic = bytes.subarray(footerStart, footerStart + MAGIC_FOOTER.length);
    if (!equalBytes(footerMagic, MAGIC_FOOTER)) {
      throw new Error("暗号化フォーマットではありません");
    }

    const payloadLength = readU32BE(bytes, footerStart + MAGIC_FOOTER.length);
    const payloadStart = footerStart - payloadLength;

    if (payloadStart < 0) {
      throw new Error("壊れたデータです");
    }

    const payload = bytes.subarray(payloadStart, footerStart);

    let o = 0;
    const magic = payload.subarray(o, o + MAGIC_PAYLOAD.length);
    o += MAGIC_PAYLOAD.length;
    if (!equalBytes(magic, MAGIC_PAYLOAD)) {
      throw new Error("ペイロードの形式が違います");
    }

    const version = payload[o++];
    if (version !== VERSION) {
      throw new Error(`未対応のバージョンです: ${version}`);
    }

    const mimeLen = payload[o++];
    const mimeType = td.decode(payload.subarray(o, o + mimeLen));
    o += mimeLen;

    const iterations = readU32BE(payload, o);
    o += 4;

    const salt = payload.subarray(o, o + SALT_LEN);
    o += SALT_LEN;

    const iv = payload.subarray(o, o + IV_LEN);
    o += IV_LEN;

    const encrypted = payload.subarray(o);

    const key = await deriveKey(password, salt, iterations);

    const plain = new Uint8Array(
      await cryptoImpl.subtle.decrypt(
        { name: "AES-GCM", iv },
        key,
        encrypted
      )
    );

    return {
      bytes: plain,
      blob: bytesToBlob(plain, mimeType || "application/octet-stream"),
      mimeType: mimeType || "application/octet-stream",
      iterations,
    };
  }

  return {
    encryptImage,
    decryptImage,
    bytesToBlob,
    toBytes,
    concatBytes,
  };
})();

if (typeof module !== "undefined" && module.exports) {
  module.exports = ImageLocker;
}
if (typeof globalThis !== "undefined") {
  globalThis.ImageLocker = ImageLocker;
}
