import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { createHash, createSign, generateKeyPairSync, randomBytes } from 'crypto';
import type { KeyObject } from 'crypto';
import {
  toBase64Url,
  fromBase64Url,
  decodeCBOR,
  generateRegistrationOptions,
  generateAuthenticationOptions,
  verifyRegistrationResponse,
  verifyAuthenticationResponse,
  PasskeyVault,
  es256DerToRaw,
  RelyingPartyConfig,
  RegistrationResponse,
  AuthenticationResponse,
  StoredPasskey,
} from '../src/lib/craft/passkeys';
import { generateCredentialKey } from '../src/lib/craft/credentials';
import { nano, macro } from '../src/lib/craft/index';

// ── Minimal CBOR encoder (test double) ────────────────────────

function encodeHead(major: number, len: number): Buffer {
  if (len < 24) return Buffer.from([(major << 5) | len]);
  if (len < 256) return Buffer.from([(major << 5) | 24, len]);
  if (len < 65536) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(len, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(len, 1);
  return b;
}

function cborEncode(value: any): Buffer {
  const chunks: Buffer[] = [];
  const encode = (v: any) => {
    if (typeof v === 'number') {
      if (Number.isInteger(v) && v >= 0) chunks.push(encodeHead(0, v));
      else if (Number.isInteger(v) && v < 0) chunks.push(encodeHead(1, -1 - v));
      else {
        const b = Buffer.alloc(8);
        b.writeDoubleBE(v, 0);
        chunks.push(Buffer.from([0xfb]), b);
      }
    } else if (typeof v === 'string') {
      const b = Buffer.from(v, 'utf-8');
      chunks.push(encodeHead(3, b.length), b);
    } else if (Buffer.isBuffer(v) || v instanceof Uint8Array) {
      const b = Buffer.from(v);
      chunks.push(encodeHead(2, b.length), b);
    } else if (v === true) chunks.push(Buffer.from([0xf5]));
    else if (v === false) chunks.push(Buffer.from([0xf4]));
    else if (v === null) chunks.push(Buffer.from([0xf6]));
    else if (Array.isArray(v)) {
      chunks.push(encodeHead(4, v.length));
      for (const item of v) encode(item);
    } else if (v instanceof Map) {
      chunks.push(encodeHead(5, v.size));
      for (const [k, val] of v) {
        encode(k);
        encode(val);
      }
    } else if (typeof v === 'object') {
      const entries = Object.entries(v);
      chunks.push(encodeHead(5, entries.length));
      for (const [k, val] of entries) {
        encode(k);
        encode(val);
      }
    } else {
      throw new Error('cborEncode: unsupported value');
    }
  };
  encode(value);
  return Buffer.concat(chunks);
}

// ── Fake WebAuthn authenticator (ES256 / P-256) ───────────────

const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const pubJwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
const credId = randomBytes(16);

const coseKey = new Map<number, any>([
  [1, 2], // kty: EC2
  [3, 1], // crv: P-256
  [-2, fromBase64Url(pubJwk.x)],
  [-3, fromBase64Url(pubJwk.y)],
]);

function buildAuthData(rpId: string, flags: number, counter: number, withAttested: boolean) {
  const rpIdHash = createHash('sha256').update(rpId).digest();
  const counterBuf = Buffer.alloc(4);
  counterBuf.writeUInt32BE(counter, 0);
  let authData = Buffer.concat([rpIdHash, Buffer.from([flags]), counterBuf]);
  if (withAttested) {
    const aaguid = Buffer.alloc(16);
    const credIdLen = Buffer.alloc(2);
    credIdLen.writeUInt16BE(credId.length, 0);
    authData = Buffer.concat([authData, aaguid, credIdLen, credId, cborEncode(coseKey)]);
  }
  return authData;
}

function makeClientData(type: string, challenge: string, origin: string): Buffer {
  return Buffer.from(JSON.stringify({ type, challenge, origin }));
}

function makeRegistrationResponse(
  rp: RelyingPartyConfig,
  options: ReturnType<typeof generateRegistrationOptions>,
  flags = 0x45, // UP | UV | AT
): RegistrationResponse {
  const clientData = makeClientData('webauthn.create', options.challenge, rp.origin);
  const authData = buildAuthData(rp.rpId, flags, 0, true);
  const attestationObject = cborEncode({ fmt: 'none', attStmt: {}, authData });
  return {
    id: toBase64Url(credId),
    rawId: toBase64Url(credId),
    type: 'public-key',
    response: {
      clientDataJSON: toBase64Url(clientData),
      attestationObject: toBase64Url(attestationObject),
    },
  };
}

function makeAuthenticationResponse(
  rp: RelyingPartyConfig,
  options: ReturnType<typeof generateAuthenticationOptions>,
  counter = 1,
  flags = 0x05, // UP | UV
  signWith: string | KeyObject = privateKey,
): AuthenticationResponse {
  const clientData = makeClientData('webauthn.get', options.challenge, rp.origin);
  const authData = buildAuthData(rp.rpId, flags, counter, false);
  const clientDataHash = createHash('sha256').update(clientData).digest();
  const derSig = createSign('sha256').update(Buffer.concat([authData, clientDataHash])).sign(signWith);
  return {
    id: toBase64Url(credId),
    rawId: toBase64Url(credId),
    type: 'public-key',
    response: {
      clientDataJSON: toBase64Url(clientData),
      authenticatorData: toBase64Url(authData),
      signature: toBase64Url(es256DerToRaw(derSig)),
    },
  };
}

const RP: RelyingPartyConfig = { rpId: 'localhost', rpName: 'CRAFT', origin: 'http://localhost:8765' };

// ── CBOR decoder ──────────────────────────────────────────────

describe('passkeys: CBOR subset', () => {
  test('decodes integers, strings, byte strings, arrays', () => {
    expect(decodeCBOR(Buffer.from([0x01]))).toBe(1);
    expect(decodeCBOR(Buffer.from([0x20]))).toBe(-1);
    expect(decodeCBOR(cborEncode('hello'))).toBe('hello');
    expect(decodeCBOR(cborEncode([1, 'two', Buffer.from([1, 2, 3])]))).toEqual([1, 'two', Buffer.from([1, 2, 3])]);
  });

  test('decodes maps with integer keys as Map', () => {
    const m = decodeCBOR(cborEncode(new Map<number, any>([[1, 'a'], [-7, Buffer.from([9])]])));
    expect(m instanceof Map).toBe(true);
    if (m instanceof Map) {
      expect(m.get(1)).toBe('a');
      expect(m.get(-7)).toEqual(Buffer.from([9]));
    }
  });

  test('rejects trailing bytes', () => {
    expect(() => decodeCBOR(Buffer.from([0x01, 0x02]))).toThrow(/trailing bytes/);
  });
});

// ── Registration ──────────────────────────────────────────────

describe('passkeys: registration', () => {
  test('a simulated device registration verifies and yields the public key', () => {
    const options = generateRegistrationOptions(RP, 'test-user');
    const response = makeRegistrationResponse(RP, options);
    const { credential } = verifyRegistrationResponse(response, options, RP);
    expect(credential.id).toBe(toBase64Url(credId));
    expect(credential.algorithm).toBe(-7);
    expect(credential.publicKeyPem).toContain('BEGIN PUBLIC KEY');
    expect(credential.counter).toBe(0);
  });

  test('wrong challenge is rejected', () => {
    const options = generateRegistrationOptions(RP, 'test-user');
    const response = makeRegistrationResponse(RP, { ...options, challenge: toBase64Url(randomBytes(32)) });
    expect(() => verifyRegistrationResponse(response, options, RP)).toThrow(/challenge mismatch/);
  });

  test('wrong origin is rejected', () => {
    const options = generateRegistrationOptions(RP, 'test-user');
    const response = makeRegistrationResponse({ ...RP, origin: 'https://evil.example' }, options);
    expect(() => verifyRegistrationResponse(response, options, RP)).toThrow(/origin mismatch/);
  });

  test('missing user-verification flag is rejected', () => {
    const options = generateRegistrationOptions(RP, 'test-user');
    const response = makeRegistrationResponse(RP, options, 0x01); // UP only, no UV
    expect(() => verifyRegistrationResponse(response, options, RP)).toThrow(/user verification/);
  });

  test('wrong rpId is rejected', () => {
    const options = generateRegistrationOptions(RP, 'test-user');
    const response = makeRegistrationResponse({ ...RP, rpId: 'evil.example' }, options);
    expect(() => verifyRegistrationResponse(response, options, RP)).toThrow(/rpIdHash/);
  });

  test('id/rawId mismatch is rejected', () => {
    const options = generateRegistrationOptions(RP, 'test-user');
    const response = makeRegistrationResponse(RP, options);
    response.id = toBase64Url(randomBytes(16));
    expect(() => verifyRegistrationResponse(response, options, RP)).toThrow(/credential id mismatch/);
  });
});

// ── Authentication (biometric assertion) ──────────────────────

describe('passkeys: authentication (unlock)', () => {
  let credential: StoredPasskey;
  beforeAll(() => {
    const options = generateRegistrationOptions(RP, 'test-user');
    const response = makeRegistrationResponse(RP, options);
    credential = verifyRegistrationResponse(response, options, RP).credential;
  });

  test('a simulated biometric assertion verifies', () => {
    const options = generateAuthenticationOptions(RP, [{ id: credential.id, transports: [] }]);
    const assertion = makeAuthenticationResponse(RP, options);
    const result = verifyAuthenticationResponse(assertion, options, credential, RP);
    expect(result.verified).toBe(true);
    expect(result.counter).toBe(1);
  });

  test('tampered signature is rejected', () => {
    const options = generateAuthenticationOptions(RP, [{ id: credential.id, transports: [] }]);
    const assertion = makeAuthenticationResponse(RP, options);
    const sig = fromBase64Url(assertion.response.signature);
    sig[10] ^= 0xff;
    assertion.response.signature = toBase64Url(sig);
    expect(() => verifyAuthenticationResponse(assertion, options, credential, RP)).toThrow(/signature/);
  });

  test('assertion from a different private key is rejected', () => {
    const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const options = generateAuthenticationOptions(RP, [{ id: credential.id, transports: [] }]);
    const assertion = makeAuthenticationResponse(RP, options, 1, 0x05, other.privateKey);
    expect(() => verifyAuthenticationResponse(assertion, options, credential, RP)).toThrow(/signature/);
  });

  test('replayed challenge is rejected', () => {
    const options = generateAuthenticationOptions(RP, [{ id: credential.id, transports: [] }]);
    const assertion = makeAuthenticationResponse(RP, { ...options, challenge: toBase64Url(randomBytes(32)) });
    expect(() => verifyAuthenticationResponse(assertion, options, credential, RP)).toThrow(/challenge mismatch/);
  });

  test('credential id mismatch is rejected', () => {
    const options = generateAuthenticationOptions(RP, [{ id: credential.id, transports: [] }]);
    const assertion = makeAuthenticationResponse(RP, options);
    assertion.id = toBase64Url(randomBytes(16));
    expect(() => verifyAuthenticationResponse(assertion, options, credential, RP)).toThrow(/credential id/);
  });
});

// ── Passkey vault ─────────────────────────────────────────────

describe('passkeys: vault', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'craft-vault-test-'));
  const cfg = {
    vaultPath: path.join(dir, 'vault.json'),
    vaultKeyPath: path.join(dir, 'vault.key'),
  };

  let credential: StoredPasskey;
  let vault: PasskeyVault;

  beforeAll(() => {
    PasskeyVault.init(cfg);
    vault = new PasskeyVault(cfg);
    const options = generateRegistrationOptions(RP, 'test-user');
    credential = verifyRegistrationResponse(makeRegistrationResponse(RP, options), options, RP).credential;
  });

  test('init refuses to overwrite an existing vault', () => {
    expect(() => PasskeyVault.init(cfg)).toThrow(/already exists/);
  });

  test('stores and unwraps a credential key', () => {
    vault.storeKey('default', 'Ab3!cDe');
    expect(vault.unwrapStored('default')).toBe('Ab3!cDe');
    expect(vault.listLabels()).toContain('default');
  });

  test('binds a passkey to a label and tracks the counter', () => {
    vault.bindPasskey(credential, 'default');
    const creds = vault.listCredentials();
    expect(creds).toHaveLength(1);
    expect(creds[0].label).toBe('default');
    expect(creds[0].credential.id).toBe(credential.id);
    vault.updateCounter(credential.id, 42);
    expect(vault.listCredentials()[0].credential.counter).toBe(42);
  });

  test('releaseKey returns the stored key after a verified assertion', () => {
    expect(vault.releaseKey('default', { verified: true })).toBe('Ab3!cDe');
  });

  test('rejects unwrapping an unknown label', () => {
    expect(() => vault.unwrapStored('nope')).toThrow(/no stored key/);
  });

  test('constructor throws when the vault key file is missing', () => {
    const badCfg = { vaultPath: path.join(dir, 'x.json'), vaultKeyPath: path.join(dir, 'x.key') };
    expect(() => new PasskeyVault(badCfg)).toThrow(/vault key not found/);
  });
});

// ── End-to-end: credential key + passkey vault ────────────────

describe('passkeys: credential-key unlock flow', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'craft-vault-e2e-'));
  const cfg = { vaultPath: path.join(dir, 'vault.json'), vaultKeyPath: path.join(dir, 'vault.key') };
  let vault: PasskeyVault;

  beforeAll(() => {
    PasskeyVault.init(cfg);
    vault = new PasskeyVault(cfg);
  });

  test('craft with a stored key, then release it via the vault to restore', async () => {
    const data = Buffer.from('passkey-protected payload — craft engine test');
    const key = generateCredentialKey();

    const crafted = await nano(data, 'vault.txt', 'text/plain', '', { credentialKey: key });
    vault.storeKey('default', key);

    // Simulate: biometric assertion verified, then the key is released.
    const released = vault.releaseKey('default', { verified: true });
    expect(released).toBe(key);

    const restored = await macro(crafted.buffer, { type: 'credentialKey', value: released });
    expect(restored.buffer.equals(data)).toBe(true);
    expect(restored.integrityVerified).toBe(true);
  });

  test('a tampered wrapped blob fails GCM authentication on unwrap', () => {
    const key = generateCredentialKey();
    vault.storeKey('tamper', key);

    const dataFile = JSON.parse(fs.readFileSync(cfg.vaultPath, 'utf-8'));
    const blob = dataFile.wrappedKeys['tamper'].wrapped;
    const raw = fromBase64Url(blob.data);
    raw[0] ^= 0xff;
    dataFile.wrappedKeys['tamper'].wrapped = { ...blob, data: toBase64Url(raw) };
    fs.writeFileSync(cfg.vaultPath, JSON.stringify(dataFile, null, 2) + '\n');

    expect(() => vault.unwrapStored('tamper')).toThrow();
  });
});
