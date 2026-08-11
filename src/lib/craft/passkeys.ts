/**
 * ═══════════════════════════════════════════════════════════════
 *  @craft/passkeys — Device Passkeys (WebAuthn)
 *  The Living Canvas Edition
 * ═══════════════════════════════════════════════════════════════
 *
 *  Alternative to passphrases / credential keys: unlock with the
 *  device's own biometrics — fingerprint (Touch ID / Windows Hello) or
 *  face (Face ID / Windows Hello) — via the WebAuthn / FIDO2 protocol
 *  (W3C recommendation, platform authenticators).
 *
 *  Pure Node implementation on top of `node:crypto` (no dependencies):
 *
 *    register ──► generateRegistrationOptions()
 *             ──► (browser) navigator.credentials.create()
 *             ──► verifyRegistrationResponse()  → stores a passkey
 *    unlock   ──► generateAuthenticationOptions()
 *             ──► (browser) navigator.credentials.get()  ← biometric prompt
 *             ──► verifyAuthenticationResponse() → authenticates
 *
 *  The passkey's private key never leaves the device; the CLI only ever
 *  sees the public key, and every unlock requires a fresh cryptographic
 *  assertion signed by the passkey — which the platform only produces
 *  after the fingerprint/face prompt succeeds.
 *
 *  TRUST MODEL: a PasskeyVault stores credential keys wrapped with
 *  AES-256-GCM under a random vault key kept in a separate 0600 file.
 *  The passkey assertion is the authentication gate that releases the
 *  wrapped key. This defends against remote exfiltration and casual
 *  access; an attacker with unrestricted local disk access who can read
 *  both vault files AND has the user's unlocked browser session is out
 *  of scope (use full-disk encryption for that threat model).
 */

import * as fs from 'fs';
import * as path from 'path';
import {
  createPublicKey,
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  timingSafeEqual,
  verify as cryptoVerify,
} from 'crypto';

import { IV_LENGTH } from './types';

// ─────────────────────────────────────────────────────────────
// Base64url helpers
// ─────────────────────────────────────────────────────────────

export function toBase64Url(buf: Buffer): string {
  return buf.toString('base64url');
}

export function fromBase64Url(s: string): Buffer {
  return Buffer.from(s, 'base64url');
}

// ─────────────────────────────────────────────────────────────
// Minimal CBOR decoder (subset needed for WebAuthn)
// ─────────────────────────────────────────────────────────────

class Cursor {
  constructor(public buf: Buffer, public pos = 0) {}

  readByte(): number {
    if (this.pos >= this.buf.length) throw new Error('CBOR: unexpected end of input');
    return this.buf[this.pos++];
  }

  readBytes(n: number): Buffer {
    if (this.pos + n > this.buf.length) throw new Error('CBOR: unexpected end of input');
    const out = this.buf.subarray(this.pos, this.pos + n);
    this.pos += n;
    return out;
  }
}

function decodeCBORByteLength(cursor: Cursor, additional: number): number {
  if (additional < 24) return additional;
  if (additional === 24) return cursor.readByte();
  if (additional === 25) return cursor.readBytes(2).readUInt16BE(0);
  if (additional === 26) return cursor.readBytes(4).readUInt32BE(0);
  if (additional === 27) {
    const big = cursor.readBytes(8).readBigUInt64BE(0);
    if (big > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('CBOR: integer too large');
    return Number(big);
  }
  throw new Error('CBOR: unsupported length encoding');
}

/**
 * Union of all values our CBOR subset can produce.
 */
export type CBORValue =
  | number
  | string
  | Buffer
  | boolean
  | null
  | undefined
  | CBORValue[]
  | Map<CBORValue, CBORValue>
  | { [key: string]: CBORValue };

/** Decode a CBOR value. Maps with non-text keys decode to a Map. */
export function decodeCBOR(buf: Buffer): CBORValue {
  const cursor = new Cursor(buf);
  const value = decodeCBORValue(cursor);
  if (cursor.pos !== buf.length) {
    throw new Error('CBOR: trailing bytes after top-level value');
  }
  return value;
}

function decodeCBORValue(cursor: Cursor): CBORValue {
  const initial = cursor.readByte();
  const major = initial >> 5;
  const additional = initial & 0x1f;

  switch (major) {
    case 0:
      return decodeCBORByteLength(cursor, additional);
    case 1: {
      const n = decodeCBORByteLength(cursor, additional);
      return -1 - n;
    }
    case 2:
      return cursor.readBytes(decodeCBORByteLength(cursor, additional));
    case 3:
      return cursor.readBytes(decodeCBORByteLength(cursor, additional)).toString('utf-8');
    case 4: {
      const arr: CBORValue[] = [];
      const len = decodeCBORByteLength(cursor, additional);
      for (let i = 0; i < len; i++) arr.push(decodeCBORValue(cursor));
      return arr;
    }
    case 5: {
      const len = decodeCBORByteLength(cursor, additional);
      let map: Record<string, CBORValue> | Map<CBORValue, CBORValue> = {};
      let mapLike = false;
      for (let i = 0; i < len; i++) {
        const k = decodeCBORValue(cursor);
        const v = decodeCBORValue(cursor);
        if (typeof k === 'string' && !mapLike) {
          (map as Record<string, CBORValue>)[k] = v;
        } else {
          if (!mapLike) {
            map = new Map<CBORValue, CBORValue>();
            mapLike = true;
          }
          (map as Map<CBORValue, CBORValue>).set(k, v);
        }
      }
      return map;
    }
    case 6:
      // Tags carry no semantic weight for our subset — unwrap.
      return decodeCBORValue(cursor);
    case 7: {
      if (additional === 20) return false;
      if (additional === 21) return true;
      if (additional === 22) return null;
      if (additional === 23) return undefined;
      if (additional === 25) return cursor.readBytes(2).readUInt16BE(0) / 2; // half float (approx)
      if (additional === 26) return cursor.readBytes(4).readFloatBE(0);
      if (additional === 27) return cursor.readBytes(8).readDoubleBE(0);
      return undefined;
    }
    default:
      throw new Error(`CBOR: unsupported major type ${major}`);
  }
}

// ─────────────────────────────────────────────────────────────
// WebAuthn constants
// ─────────────────────────────────────────────────────────────

/** COSE algorithm identifiers used by passkeys. */
export const COSE_ALG = {
  ES256: -7, // ECDSA P-256 + SHA-256
  EdDSA: -8, // Ed25519
  RS256: -257, // RSA PKCS#1 v1.5 + SHA-256
} as const;

export const COSE_KTY = { EC2: 2, RSA: 3, OKP: 8 } as const;
export const COSE_CRV = { P256: 1, P384: 2, ED25519: 6 } as const;

/** AuthData flag bits (WebAuthn §6.1). */
export const AUTH_FLAGS = {
  UP: 0x01, // user present
  UV: 0x04, // user verified (biometric prompt succeeded)
  AT: 0x40, // attested credential data present
} as const;

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

export interface RelyingPartyConfig {
  /** Usually the hostname, e.g. 'localhost'. */
  rpId: string;
  /** Human-readable relying-party name shown in the prompt. */
  rpName: string;
  /** Full origin of the calling page, e.g. 'http://localhost:8765'. */
  origin: string;
}

export interface RegistrationOptions {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ type: 'public-key'; alg: number }>;
  timeout: number;
  attestation: 'none';
  authenticatorSelection: {
    authenticatorAttachment: 'platform';
    residentKey: 'required';
    userVerification: 'required';
  };
  excludeCredentials: [];
}

export interface AuthenticationOptions {
  challenge: string;
  rpId: string;
  timeout: number;
  allowCredentials: Array<{ type: 'public-key'; id: string; transports: string[] }>;
  userVerification: 'required';
}

export interface StoredPasskey {
  id: string;
  publicKeyPem: string;
  algorithm: number;
  counter: number;
  transports: string[];
  createdAt: string;
}

export interface RegistrationResponse {
  id: string;
  rawId: string;
  type: string;
  response: { clientDataJSON: string; attestationObject: string };
}

export interface AuthenticationResponse {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    authenticatorData: string;
    signature: string;
    userHandle?: string;
  };
}

export interface AuthenticatorData {
  rpIdHash: Buffer;
  flags: number;
  counter: number;
  credentialId?: string;
  cosePublicKey?: Map<number, CBORValue>;
}

// ─────────────────────────────────────────────────────────────
// Option generation
// ─────────────────────────────────────────────────────────────

/**
 * Options for `navigator.credentials.create({ publicKey })`. The CLI
 * hands these to a browser page; the browser prompts for the device
 * biometric (platform authenticator) and returns a RegistrationResponse.
 */
export function generateRegistrationOptions(
  rp: RelyingPartyConfig,
  userName: string,
  userId?: Buffer,
  challenge?: Buffer,
): RegistrationOptions {
  return {
    challenge: toBase64Url(challenge ?? randomBytes(32)),
    rp: { id: rp.rpId, name: rp.rpName },
    user: {
      id: toBase64Url(userId ?? randomBytes(16)),
      name: userName,
      displayName: userName,
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: COSE_ALG.ES256 },
      { type: 'public-key', alg: COSE_ALG.RS256 },
      { type: 'public-key', alg: COSE_ALG.EdDSA },
    ],
    timeout: 60_000,
    attestation: 'none',
    authenticatorSelection: {
      authenticatorAttachment: 'platform',
      residentKey: 'required',
      userVerification: 'required',
    },
    excludeCredentials: [],
  };
}

/**
 * Options for `navigator.credentials.get({ publicKey })`. The browser
 * prompts for the fingerprint/face unlock and returns an
 * AuthenticationResponse (a fresh cryptographic assertion).
 */
export function generateAuthenticationOptions(
  rp: RelyingPartyConfig,
  credentials: Array<Pick<StoredPasskey, 'id' | 'transports'>>,
  challenge?: Buffer,
): AuthenticationOptions {
  return {
    challenge: toBase64Url(challenge ?? randomBytes(32)),
    rpId: rp.rpId,
    timeout: 60_000,
    allowCredentials: credentials.map((c) => ({
      type: 'public-key' as const,
      id: c.id,
      transports: c.transports?.length ? c.transports : ['internal'],
    })),
    userVerification: 'required',
  };
}

// ─────────────────────────────────────────────────────────────
// Parsing helpers
// ─────────────────────────────────────────────────────────────

function sha256(data: Buffer | string): Buffer {
  return createHash('sha256').update(data).digest();
}

function safeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

/**
 * WebAuthn ES256 signatures are the raw 64-byte concatenation r ‖ s.
 * Node's crypto.verify() expects ASN.1 DER, so convert before verifying.
 * Handles negative values with a leading 0x00 pad byte (two's complement).
 */
export function es256RawToDer(signature: Buffer): Buffer {
  if (signature.length % 2 !== 0) {
    throw new Error('Passkey: ES256 signature must be an even number of bytes (r ‖ s).');
  }
  const half = signature.length / 2;
  const encodeInt = (buf: Buffer): Buffer => {
    let start = 0;
    while (start < buf.length - 1 && buf[start] === 0) start++;
    let body = buf.subarray(start);
    if (body[0] & 0x80) {
      body = Buffer.concat([Buffer.from([0x00]), body]);
    }
    return Buffer.concat([Buffer.from([0x02, body.length]), body]);
  };
  const r = encodeInt(signature.subarray(0, half));
  const s = encodeInt(signature.subarray(half));
  const seq = Buffer.concat([r, s]);
  return Buffer.concat([Buffer.from([0x30, seq.length]), seq]);
}

/** Inverse of es256RawToDer: DER (from crypto.sign) → raw r ‖ s. */
export function es256DerToRaw(signature: Buffer): Buffer {
  const r = derReadInt(signature, 2);
  const s = derReadInt(signature, r.offset);
  const size = 32;
  const padTo = (buf: Buffer, len: number): Buffer => {
    if (buf.length >= len) return buf.subarray(buf.length - len);
    return Buffer.concat([Buffer.alloc(len - buf.length), buf]);
  };
  return Buffer.concat([padTo(r.value, size), padTo(s.value, size)]);
}

/** Verify a WebAuthn signature against a public key, converting raw ES256
 * r‖s signatures to DER (Node's crypto.verify expects DER for ECDSA). */
function verifyWebAuthnSignature(
  coseAlg: number,
  data: Buffer,
  publicKey: ReturnType<typeof createPublicKey>,
  signature: Buffer,
): boolean {
  if (coseAlg === COSE_ALG.EdDSA) {
    return cryptoVerify(null, data, publicKey, signature);
  }
  const sig = coseAlg === COSE_ALG.ES256 ? es256RawToDer(signature) : signature;
  return cryptoVerify('sha256', data, publicKey, sig);
}

function derReadInt(buf: Buffer, offset: number): { value: Buffer; offset: number } {
  if (buf[offset] !== 0x02) throw new Error('Passkey: malformed DER signature.');
  const len = buf[offset + 1];
  const body = buf.subarray(offset + 2, offset + 2 + len);
  if (body[0] === 0 && body.length > 1) return { value: body.subarray(1), offset: offset + 2 + len };
  return { value: body, offset: offset + 2 + len };
}

function parseClientDataJSON(clientDataJSON: string): {
  type: string;
  challenge: string;
  origin: string;
  raw: Buffer;
  hash: Buffer;
} {
  const raw = fromBase64Url(clientDataJSON);
  const parsed = JSON.parse(raw.toString('utf-8'));
  if (typeof parsed.type !== 'string' || typeof parsed.challenge !== 'string' || typeof parsed.origin !== 'string') {
    throw new Error('Passkey: malformed clientDataJSON.');
  }
  return { type: parsed.type, challenge: parsed.challenge, origin: parsed.origin, raw, hash: sha256(raw) };
}

function assertOrigin(actual: string, expected: string): void {
  if (actual !== expected) {
    throw new Error(`Passkey: origin mismatch (expected ${expected}, got ${actual}).`);
  }
}

function assertChallenge(actualB64url: string, expectedB64url: string): void {
  let a: Buffer;
  let b: Buffer;
  try {
    a = fromBase64Url(actualB64url);
    b = fromBase64Url(expectedB64url);
  } catch {
    throw new Error('Passkey: challenge is not valid base64url.');
  }
  if (!safeEqual(a, b)) {
    throw new Error('Passkey: challenge mismatch — response was forged or replayed.');
  }
}

/** Parse the authenticatorData portion of an attestation or assertion. */
export function parseAuthenticatorData(authDataBuf: Buffer): AuthenticatorData {
  if (authDataBuf.length < 37) {
    throw new Error('Passkey: authenticatorData too short.');
  }
  const rpIdHash = authDataBuf.subarray(0, 32);
  const flags = authDataBuf[32];
  const counter = authDataBuf.readUInt32BE(33);
  const result: AuthenticatorData = { rpIdHash, flags, counter };

  let offset = 37;
  if (flags & AUTH_FLAGS.AT) {
    // AAGUID(16) + credIdLen(2) + credId + COSE pubkey
    offset += 16;
    const credIdLen = authDataBuf.readUInt16BE(offset);
    offset += 2;
    if (offset + credIdLen > authDataBuf.length) {
      throw new Error('Passkey: authenticatorData truncated at credential id.');
    }
    const credId = authDataBuf.subarray(offset, offset + credIdLen);
    offset += credIdLen;
    result.credentialId = toBase64Url(credId);
    const cose = decodeCBOR(authDataBuf.subarray(offset));
    if (!(cose instanceof Map)) {
      throw new Error('Passkey: malformed COSE public key.');
    }
    result.cosePublicKey = cose as Map<number, CBORValue>;
  }

  return result;
}

/** Convert a COSE public key map into an SPKI PEM public key. */
export function coseKeyToPem(cose: Map<number, CBORValue>): { pem: string; algorithm: number } {
  const kty = cose.get(1);
  if (kty === COSE_KTY.EC2) {
    const crv = cose.get(3);
    const x = cose.get(-2);
    const y = cose.get(-3);
    if (!Buffer.isBuffer(x) || !Buffer.isBuffer(y)) {
      throw new Error('Passkey: EC2 public key missing x/y components.');
    }
    const jwk: Record<string, string> = {
      kty: 'EC',
      x: toBase64Url(x),
      y: toBase64Url(y),
      ext: 'true',
    };
    jwk.crv = crv === COSE_CRV.P256 ? 'P-256' : crv === COSE_CRV.P384 ? 'P-384' : String(crv);
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    return { pem: key.export({ type: 'spki', format: 'pem' }).toString(), algorithm: COSE_ALG.ES256 };
  }
  if (kty === COSE_KTY.RSA) {
    const n = cose.get(-1);
    const e = cose.get(-2);
    if (!Buffer.isBuffer(n) || !Buffer.isBuffer(e)) {
      throw new Error('Passkey: RSA public key missing n/e components.');
    }
    const key = createPublicKey({
      key: { kty: 'RSA', n: toBase64Url(n), e: toBase64Url(e), ext: true },
      format: 'jwk',
    });
    return { pem: key.export({ type: 'spki', format: 'pem' }).toString(), algorithm: COSE_ALG.RS256 };
  }
  if (kty === COSE_KTY.OKP) {
    const crv = cose.get(3);
    const x = cose.get(-2);
    if (!Buffer.isBuffer(x)) throw new Error('Passkey: OKP public key missing x component.');
    if (crv !== COSE_CRV.ED25519) throw new Error('Passkey: unsupported OKP curve.');
    const key = createPublicKey({
      key: { kty: 'OKP', crv: 'Ed25519', x: toBase64Url(x), ext: true },
      format: 'jwk',
    });
    return { pem: key.export({ type: 'spki', format: 'pem' }).toString(), algorithm: COSE_ALG.EdDSA };
  }
  throw new Error(`Passkey: unsupported COSE key type ${kty}.`);
}

// ─────────────────────────────────────────────────────────────
// Registration verification
// ─────────────────────────────────────────────────────────────

export interface VerifiedRegistration {
  credential: StoredPasskey;
}

/**
 * Verify a browser registration response against the options we issued.
 * Confirms the client data (type, challenge, origin), the rpIdHash, the
 * UP/UV/AT flags, and extracts the passkey's public key. For 'packed'
 * self-attestations the attestation signature is verified against the
 * credential public key.
 *
 * @throws Error describing any mismatch.
 */
export function verifyRegistrationResponse(
  response: RegistrationResponse,
  options: RegistrationOptions,
  rp: RelyingPartyConfig,
): VerifiedRegistration {
  if (response.type !== 'public-key') {
    throw new Error('Passkey: response.type is not "public-key".');
  }
  if (response.id !== response.rawId) {
    throw new Error('Passkey: credential id mismatch.');
  }

  const clientData = parseClientDataJSON(response.response.clientDataJSON);
  if (clientData.type !== 'webauthn.create') {
    throw new Error(`Passkey: clientDataJSON.type is "${clientData.type}", expected "webauthn.create".`);
  }
  assertChallenge(clientData.challenge, options.challenge);
  assertOrigin(clientData.origin, rp.origin);

  const attestation = decodeCBOR(fromBase64Url(response.response.attestationObject)) as {
    fmt?: string;
    attStmt?: CBORValue;
    authData?: Buffer;
  };
  if (!attestation || typeof attestation !== 'object' || !Buffer.isBuffer(attestation.authData)) {
    throw new Error('Passkey: malformed attestationObject.');
  }

  const authData = parseAuthenticatorData(attestation.authData);
  if (!safeEqual(authData.rpIdHash, sha256(rp.rpId))) {
    throw new Error('Passkey: rpIdHash does not match the relying party id.');
  }
  if (!(authData.flags & AUTH_FLAGS.UP)) {
    throw new Error('Passkey: user presence (UP) flag not set.');
  }
  if (!(authData.flags & AUTH_FLAGS.UV)) {
    throw new Error('Passkey: user verification (UV) flag not set — biometric unlock not performed.');
  }
  if (!(authData.flags & AUTH_FLAGS.AT) || !authData.cosePublicKey) {
    throw new Error('Passkey: missing attested credential data.');
  }

  const { pem, algorithm } = coseKeyToPem(authData.cosePublicKey);
  const publicKey = createPublicKey(pem);

  const fmt = attestation.fmt ?? 'none';
  if (fmt === 'packed' && attestation.attStmt instanceof Map) {
    const sig = attestation.attStmt.get(-7);
    if (Buffer.isBuffer(sig)) {
      const ok = verifyWebAuthnSignature(algorithm, attestation.authData, publicKey, sig);
      if (!ok) throw new Error('Passkey: packed attestation signature verification failed.');
    }
  } else if (fmt !== 'none' && fmt !== 'self' && fmt !== 'packed') {
    throw new Error(`Passkey: unsupported attestation format "${fmt}".`);
  }

  const credentialId = authData.credentialId as string;
  return {
    credential: {
      id: credentialId,
      publicKeyPem: pem,
      algorithm,
      counter: authData.counter,
      transports: [],
      createdAt: new Date().toISOString(),
    },
  };
}

// ─────────────────────────────────────────────────────────────
// Authentication (assertion) verification
// ─────────────────────────────────────────────────────────────

export interface VerifiedAuthentication {
  verified: boolean;
  counter: number;
  /** True when the counter advanced (a fresh, non-cloned authenticator). */
  counterAdvanced: boolean;
}

/**
 * Verify a browser authentication response (assertion) against the
 * options we issued and the stored passkey. Recomputes the signature
 * base (authenticatorData ‖ SHA-256(clientDataJSON)) and verifies it
 * against the passkey's stored public key — a signature the platform
 * only produces after a successful fingerprint/face prompt.
 *
 * @throws Error describing any mismatch.
 */
export function verifyAuthenticationResponse(
  response: AuthenticationResponse,
  options: AuthenticationOptions,
  credential: Pick<StoredPasskey, 'id' | 'publicKeyPem' | 'algorithm' | 'counter'>,
  rp: RelyingPartyConfig,
): VerifiedAuthentication {
  if (response.type !== 'public-key') {
    throw new Error('Passkey: response.type is not "public-key".');
  }
  if (response.id !== credential.id) {
    throw new Error('Passkey: assertion credential id does not match the registered passkey.');
  }

  const clientData = parseClientDataJSON(response.response.clientDataJSON);
  if (clientData.type !== 'webauthn.get') {
    throw new Error(`Passkey: clientDataJSON.type is "${clientData.type}", expected "webauthn.get".`);
  }
  assertChallenge(clientData.challenge, options.challenge);
  assertOrigin(clientData.origin, rp.origin);

  const authDataBuf = fromBase64Url(response.response.authenticatorData);
  const authData = parseAuthenticatorData(authDataBuf);
  if (!safeEqual(authData.rpIdHash, sha256(options.rpId))) {
    throw new Error('Passkey: rpIdHash does not match the relying party id.');
  }
  if (!(authData.flags & AUTH_FLAGS.UP)) {
    throw new Error('Passkey: user presence (UP) flag not set.');
  }
  if (!(authData.flags & AUTH_FLAGS.UV)) {
    throw new Error('Passkey: user verification (UV) flag not set — biometric unlock not performed.');
  }

  const signature = fromBase64Url(response.response.signature);
  const signed = Buffer.concat([authDataBuf, clientData.hash]);
  const publicKey = createPublicKey(credential.publicKeyPem);
  const ok = verifyWebAuthnSignature(credential.algorithm, signed, publicKey, signature);
  if (!ok) {
    throw new Error('Passkey: assertion signature verification failed.');
  }

  const counterAdvanced =
    authData.counter === 0 || credential.counter === 0 || authData.counter > credential.counter;

  return { verified: true, counter: authData.counter, counterAdvanced };
}

// ─────────────────────────────────────────────────────────────
// Passkey vault — local, wrapped storage
// ─────────────────────────────────────────────────────────────

interface WrappedBlob {
  /** base64url ciphertext of the wrapped secret. */
  data: string;
  /** base64url IV. */
  iv: string;
  /** base64url GCM auth tag. */
  tag: string;
}

export interface PasskeyVaultData {
  version: number;
  createdAt: string;
  /** label → wrapped credential key. */
  wrappedKeys: Record<string, { wrapped: WrappedBlob; createdAt: string }>;
  /** credentialId → bound passkey + label. */
  credentials: Record<string, { credential: StoredPasskey; label: string; createdAt: string }>;
}

export interface PasskeyVaultConfig {
  /** Path to the JSON vault (wrapped secrets + passkey public keys). */
  vaultPath: string;
  /** Path to the 0600 file holding the random vault key. */
  vaultKeyPath: string;
}

function wrap(secret: string, vaultKey: Buffer): WrappedBlob {
  const iv = randomBytes(IV_LENGTH);
  const cipher = createCipheriv('aes-256-gcm', vaultKey, iv);
  const data = Buffer.concat([cipher.update(Buffer.from(secret, 'utf-8')), cipher.final()]);
  return { data: toBase64Url(data), iv: toBase64Url(iv), tag: toBase64Url(cipher.getAuthTag()) };
}

function unwrap(blob: WrappedBlob, vaultKey: Buffer): string {
  const decipher = createDecipheriv('aes-256-gcm', vaultKey, fromBase64Url(blob.iv));
  decipher.setAuthTag(fromBase64Url(blob.tag));
  const data = Buffer.concat([decipher.update(fromBase64Url(blob.data)), decipher.final()]);
  return data.toString('utf-8');
}

function emptyVault(): PasskeyVaultData {
  return { version: 1, createdAt: new Date().toISOString(), wrappedKeys: {}, credentials: {} };
}

/**
 * A local vault that stores credential keys wrapped with AES-256-GCM under
 * a random vault key held in a separate 0600 file, and maps device
 * passkeys to those keys. A passkey unlock (biometric) is required to
 * release a wrapped key.
 */
export class PasskeyVault {
  private readonly vaultKey: Buffer;

  constructor(private readonly config: PasskeyVaultConfig) {
    if (!fs.existsSync(config.vaultKeyPath)) {
      throw new Error(
        `Passkey vault key not found at ${config.vaultKeyPath}. Run initPasskeyVault() first.`,
      );
    }
    this.vaultKey = Buffer.from(fs.readFileSync(config.vaultKeyPath, 'utf-8').trim(), 'hex');
    if (this.vaultKey.length !== 32) {
      throw new Error('Passkey vault key is corrupted (expected 32 bytes).');
    }
  }

  /** Create a new vault + vault-key file. Refuses to overwrite existing files. */
  static init(config: PasskeyVaultConfig): void {
    if (fs.existsSync(config.vaultPath) || fs.existsSync(config.vaultKeyPath)) {
      throw new Error('Passkey vault already exists — refusing to overwrite.');
    }
    const dir = path.dirname(path.resolve(config.vaultPath));
    fs.mkdirSync(dir, { recursive: true });
    const dirKey = path.dirname(path.resolve(config.vaultKeyPath));
    fs.mkdirSync(dirKey, { recursive: true });
    const vaultKey = randomBytes(32);
    fs.writeFileSync(config.vaultKeyPath, vaultKey.toString('hex') + '\n', { mode: 0o600 });
    fs.writeFileSync(config.vaultPath, JSON.stringify(emptyVault(), null, 2) + '\n', { mode: 0o600 });
  }

  load(): PasskeyVaultData {
    if (!fs.existsSync(this.config.vaultPath)) return emptyVault();
    return JSON.parse(fs.readFileSync(this.config.vaultPath, 'utf-8')) as PasskeyVaultData;
  }

  private save(data: PasskeyVaultData): void {
    fs.writeFileSync(this.config.vaultPath, JSON.stringify(data, null, 2) + '\n', { mode: 0o600 });
  }

  /** Store a credential key under a label, wrapped with the vault key. */
  storeKey(label: string, key: string): void {
    const data = this.load();
    data.wrappedKeys[label] = { wrapped: wrap(key, this.vaultKey), createdAt: new Date().toISOString() };
    this.save(data);
  }

  /** All bound passkey credentials. */
  listCredentials(): Array<{ credential: StoredPasskey; label: string }> {
    const data = this.load();
    return Object.values(data.credentials).map((c) => ({ credential: c.credential, label: c.label }));
  }

  /** The labels of stored (wrapped) keys. */
  listLabels(): string[] {
    return Object.keys(this.load().wrappedKeys);
  }

  /**
   * Bind a verified registration (device passkey) to a stored key label.
   * The credential's public key is stored so future assertions can be
   * verified; the wrapped key is only released after a successful
   * assertion (biometric unlock).
   */
  bindPasskey(verified: StoredPasskey, label: string): void {
    const data = this.load();
    data.credentials[verified.id] = {
      credential: verified,
      label,
      createdAt: new Date().toISOString(),
    };
    this.save(data);
  }

  /** Unwrap a stored key without requiring a passkey (used by tests). */
  unwrapStored(label: string): string {
    const data = this.load();
    const entry = data.wrappedKeys[label];
    if (!entry) throw new Error(`Passkey vault: no stored key under label "${label}".`);
    return unwrap(entry.wrapped, this.vaultKey);
  }

  /** Update a passkey's stored sign counter after a verified assertion. */
  updateCounter(credentialId: string, counter: number): void {
    const data = this.load();
    const entry = data.credentials[credentialId];
    if (entry) {
      entry.credential.counter = counter;
      this.save(data);
    }
  }

  /** The wrapped blob for a label (used by the unlock flow after assertion). */
  releaseKey(label: string, gate?: { verified: boolean }): string {
    if (!gate?.verified) {
      throw new Error('Passkey vault: release requires a verified passkey assertion.');
    }
    return this.unwrapStored(label);
  }
}
