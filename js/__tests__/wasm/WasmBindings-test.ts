import {beforeAll, describe, expect, test} from '@jest/globals';
import {generateKeyPairSync, sign} from 'crypto';
import {existsSync, readFileSync} from 'fs';
import path from 'path';
import type {Decryptor, Encryptor, MainModule, Session} from '../../wasm/libdave';

async function loadDave(): Promise<MainModule> {
  const wasmPath = path.join(__dirname, '../../wasm/libdave.wasm');
  if (!existsSync(wasmPath)) {
    throw new Error('No wasm build in js/wasm: run `make wasm` in cpp/ and copy libdave.{js,wasm,d.ts} there');
  }
  const {default: factory} = await import('../../wasm/libdave.js');
  const binary = readFileSync(wasmPath);
  return factory({
    instantiateWasm(imports: WebAssembly.Imports, done: (instance: WebAssembly.Instance) => void) {
      WebAssembly.instantiate(binary, imports).then((result) => done(result.instance));
      return {};
    },
  });
}

let dave: MainModule;

beforeAll(async () => {
  dave = await loadDave();
  dave.SetLogSeverity(dave.LoggingSeverity.LS_NONE);
});

const PROTOCOL_VERSION = 1;
const GROUP_ID = 1234567890n;
const USER_A = '1234123412341234';
const USER_B = '5678567856785678';

type Bytes = Uint8Array | number[];

function concat(...parts: Bytes[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function uint(value: number | bigint, size: number): Uint8Array {
  const out = new Uint8Array(size);
  let remaining = BigInt(value);
  for (let i = size - 1; i >= 0; i--) {
    out[i] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return out;
}

function opaque(data: Bytes): Uint8Array {
  const length = data.length;
  const prefix = length < 0x40 ? uint(length, 1) : length < 0x4000 ? uint(0x4000 | length, 2) : uint(0x80000000 | length, 4);
  return concat(prefix, data);
}

class Reader {
  offset = 0;

  constructor(private readonly bytes: Uint8Array) {}

  uint(size: number): number {
    let value = 0;
    for (let i = 0; i < size; i++) {
      value = value * 256 + this.bytes[this.offset++]!;
    }
    return value;
  }

  skipOpaque() {
    const prefixSize = 1 << (this.bytes[this.offset]! >> 6);
    let length = this.bytes[this.offset++]! & 0x3f;
    for (let i = 1; i < prefixSize; i++) {
      length = length * 256 + this.bytes[this.offset++]!;
    }
    this.offset += length;
  }

  skipLeafNode() {
    this.skipOpaque(); // encryption_key
    this.skipOpaque(); // signature_key
    this.uint(2); // credential_type, basic
    this.skipOpaque(); // identity
    for (let i = 0; i < 5; i++) {
      this.skipOpaque(); // capabilities
    }
    const source = this.uint(1);
    if (source === 1) {
      this.offset += 16;
    } else if (source === 3) {
      this.skipOpaque();
    }
    this.skipOpaque(); // extensions
    this.skipOpaque(); // signature
  }
}

// Splits ProcessProposals output, a public commit MLSMessage followed by an optional Welcome
function splitCommitWelcome(commitWelcome: ArrayBuffer): {commit: Uint8Array; welcome: Uint8Array} {
  const bytes = new Uint8Array(commitWelcome);
  const reader = new Reader(bytes);
  reader.uint(4); // version, wire_format
  reader.skipOpaque(); // group_id
  reader.uint(8); // epoch
  const senderType = reader.uint(1);
  reader.uint(4); // sender index
  reader.skipOpaque(); // authenticated_data
  expect(reader.uint(1)).toBe(3); // commit
  reader.skipOpaque(); // proposals
  if (reader.uint(1) === 1) {
    reader.skipLeafNode();
    reader.skipOpaque(); // path nodes
  }
  reader.skipOpaque(); // signature
  reader.skipOpaque(); // confirmation_tag
  if (senderType === 1) {
    reader.skipOpaque(); // membership_tag
  }
  return {commit: bytes.slice(0, reader.offset), welcome: bytes.slice(reader.offset)};
}

// The voice gateway's role: signs external proposals in Discord's proposals wire format
class ExternalSender {
  private readonly keys = generateKeyPairSync('ec', {namedCurve: 'P-256'});

  marshalled(): Uint8Array {
    const jwk = this.keys.publicKey.export({format: 'jwk'});
    const publicKey = concat([4], Buffer.from(jwk.x!, 'base64url'), Buffer.from(jwk.y!, 'base64url'));
    return concat(opaque(publicKey), uint(1, 2), opaque([0, 1, 1, 0]));
  }

  proposeAdd(epoch: number, keyPackage: ArrayBuffer): Uint8Array {
    return this.propose(epoch, concat(uint(1, 2), new Uint8Array(keyPackage)));
  }

  proposeRemove(epoch: number, leafIndex: number): Uint8Array {
    return this.propose(epoch, concat(uint(3, 2), uint(leafIndex, 4)));
  }

  private propose(epoch: number, proposal: Uint8Array): Uint8Array {
    const header = concat(uint(1, 2), uint(1, 2));
    const content = concat(opaque(uint(GROUP_ID, 8)), uint(epoch, 8), [2], uint(0, 4), opaque([]), [2], proposal);
    const toBeSigned = concat(opaque(Buffer.from('MLS 1.0 FramedContentTBS')), opaque(concat(header, content)));
    const signature = sign('sha256', toBeSigned, this.keys.privateKey);
    return concat([0], opaque(concat(header, content, opaque(signature))));
  }
}

type InputKind = 'ArrayBuffer' | 'Uint8Array' | 'subarray' | 'DataView' | 'Array';
const INPUT_KINDS: InputKind[] = ['ArrayBuffer', 'Uint8Array', 'subarray', 'DataView', 'Array'];

function asInput(kind: InputKind, data: Uint8Array | ArrayBuffer): ArrayBuffer | ArrayBufferView | number[] {
  const bytes = new Uint8Array(data);
  switch (kind) {
    case 'ArrayBuffer':
      return bytes.slice().buffer;
    case 'Uint8Array':
      return bytes.slice();
    case 'Array':
      return Array.from(bytes);
    case 'subarray':
    case 'DataView': {
      const padded = new Uint8Array(bytes.length + 16).fill(0xee);
      padded.set(bytes, 8);
      return kind === 'subarray'
        ? padded.subarray(8, 8 + bytes.length)
        : new DataView(padded.buffer, 8, bytes.length);
    }
  }
}

function expectOwnedArrayBuffer(value: unknown): asserts value is ArrayBuffer {
  expect(value).toBeInstanceOf(ArrayBuffer);
  expect(value).not.toBe(dave.HEAPU8.buffer);
}

function makeSession(userId: string): Session {
  const session = new dave.Session('', '', (source: string, reason: string) => {
    throw new Error(`MLS failure for ${userId}: ${source} ${reason}`);
  });
  session.Init(PROTOCOL_VERSION, GROUP_ID, userId, null);
  return session;
}

function establishGroup(kind: InputKind) {
  const externalSender = new ExternalSender();
  const creator = makeSession(USER_A);
  const joiner = makeSession(USER_B);
  creator.SetExternalSender(asInput(kind, externalSender.marshalled()));
  joiner.SetExternalSender(asInput(kind, externalSender.marshalled()));
  creator.AddRecognizedUser(USER_B);
  joiner.AddRecognizedUser(USER_A);

  const keyPackage = joiner.GetMarshalledKeyPackage();
  const commitWelcome = creator.ProcessProposals(asInput(kind, externalSender.proposeAdd(0, keyPackage)));
  expect(commitWelcome).not.toBeNull();
  const {commit, welcome} = splitCommitWelcome(commitWelcome!);

  const commitResult = creator.ProcessCommit(asInput(kind, commit));
  const welcomeRoster = joiner.ProcessWelcome(asInput(kind, welcome));

  return {externalSender, creator, joiner, keyPackage, commitWelcome: commitWelcome!, commit, welcome, commitResult, welcomeRoster};
}

describe('wasm byte outputs', () => {
  test('are owned ArrayBuffers sized to their data', () => {
    const group = establishGroup('Uint8Array');
    const {creator, joiner, keyPackage, commitWelcome, commit, welcome, commitResult, welcomeRoster} = group;

    expectOwnedArrayBuffer(keyPackage);
    expect(Array.from(new Uint8Array(keyPackage, 0, 4))).toEqual([0, 1, 0, 2]); // mls10, P256_AES128GCM_SHA256_P256

    expectOwnedArrayBuffer(commitWelcome);
    expect(commit.length).toBeGreaterThan(0);
    expect(welcome.length).toBeGreaterThan(0);
    expect(commitWelcome.byteLength).toBe(commit.length + welcome.length);

    expect(commitResult.failed).toBe(false);
    expect(commitResult.ignored).toBe(false);
    const rosterUpdate = commitResult.rosterUpdate!;
    expect(Object.keys(rosterUpdate).sort()).toEqual([USER_A, USER_B]);
    expectOwnedArrayBuffer(rosterUpdate[USER_B]);
    expect(rosterUpdate[USER_B]!.byteLength).toBe(65);

    expect(Object.keys(welcomeRoster!).sort()).toEqual([USER_A, USER_B]);
    for (const value of Object.values(welcomeRoster!)) {
      expectOwnedArrayBuffer(value);
    }
    expect(new Uint8Array(welcomeRoster![USER_B]!)).toEqual(new Uint8Array(rosterUpdate[USER_B]!));

    const creatorAuthenticator = creator.GetLastEpochAuthenticator();
    const joinerAuthenticator = joiner.GetLastEpochAuthenticator();
    expectOwnedArrayBuffer(creatorAuthenticator);
    expect(creatorAuthenticator.byteLength).toBe(32);
    expect(new Uint8Array(joinerAuthenticator)).toEqual(new Uint8Array(creatorAuthenticator));

    for (const userId of [USER_A, USER_B]) {
      const creatorRatchet = creator.GetKeyRatchet(userId)!;
      const joinerRatchet = joiner.GetKeyRatchet(userId)!;
      expectOwnedArrayBuffer(creatorRatchet.baseSecret);
      expect(creatorRatchet.baseSecret.byteLength).toBe(16);
      expect(joinerRatchet.cipherSuite).toBe(creatorRatchet.cipherSuite);
      expect(new Uint8Array(joinerRatchet.baseSecret)).toEqual(new Uint8Array(creatorRatchet.baseSecret));
    }
  });

  test('roster removals are empty ArrayBuffers', () => {
    const {externalSender, creator} = establishGroup('Uint8Array');

    const commitWelcome = creator.ProcessProposals(externalSender.proposeRemove(1, 1))!;
    const {commit, welcome} = splitCommitWelcome(commitWelcome);
    expect(welcome.length).toBe(0);

    const rosterUpdate = creator.ProcessCommit(commit).rosterUpdate!;
    expectOwnedArrayBuffer(rosterUpdate[USER_B]);
    expect(rosterUpdate[USER_B]!.byteLength).toBe(0);

  });
});

describe('wasm byte inputs', () => {
  test.each(INPUT_KINDS)('%s inputs drive the session', (kind) => {
    const {creator, joiner, commitResult, welcomeRoster} = establishGroup(kind);

    expect(commitResult.failed).toBe(false);
    expect(Object.keys(commitResult.rosterUpdate!).sort()).toEqual([USER_A, USER_B]);
    expect(Object.keys(welcomeRoster!).sort()).toEqual([USER_A, USER_B]);
    expect(new Uint8Array(joiner.GetLastEpochAuthenticator())).toEqual(new Uint8Array(creator.GetLastEpochAuthenticator()));
  });

  test.each([undefined, 'abc', 16, {length: 16}])('non-byte input %p is rejected', (input) => {
    const session = makeSession(USER_A);
    expect(() => session.SetExternalSender(input as any)).toThrow(TypeError);
    expect(() => session.ProcessCommit(input as any)).toThrow(TypeError);
  });
});

describe('wasm key ratchets', () => {
  const frame = Uint8Array.from({length: 40}, (_, i) => i);

  function encrypt(encryptor: Encryptor): Uint8Array {
    const capacity = encryptor.GetMaxCiphertextByteSize(dave.MediaType.Audio, frame.length);
    const pointer = dave._malloc(capacity);
    dave.HEAPU8.set(frame, pointer);
    const written = encryptor.Encrypt(dave.MediaType.Audio, 1, pointer, frame.length, capacity);
    const ciphertext = dave.HEAPU8.slice(pointer, pointer + written);
    dave._free(pointer);
    return ciphertext;
  }

  function decrypt(decryptor: Decryptor, ciphertext: Uint8Array): Uint8Array {
    const capacity = Math.max(ciphertext.length, decryptor.GetMaxPlaintextByteSize(dave.MediaType.Audio, ciphertext.length));
    const pointer = dave._malloc(capacity);
    dave.HEAPU8.set(ciphertext, pointer);
    const written = decryptor.Decrypt(dave.MediaType.Audio, pointer, ciphertext.length, capacity);
    const plaintext = dave.HEAPU8.slice(pointer, pointer + written);
    dave._free(pointer);
    return plaintext;
  }

  function makeEncryptor(): Encryptor {
    const encryptor = new dave.Encryptor();
    encryptor.AssignSsrcToCodec(1, dave.Codec.Opus);
    return encryptor;
  }

  test('round trip through every baseSecret byte type', () => {
    const {creator} = establishGroup('Uint8Array');
    const ratchet = creator.GetKeyRatchet(USER_A)!;

    const ciphertexts = INPUT_KINDS.map((kind) => {
      const encryptor = makeEncryptor();
      encryptor.SetKeyRatchet({cipherSuite: ratchet.cipherSuite, baseSecret: asInput(kind, ratchet.baseSecret)});
      const ciphertext = encrypt(encryptor);
      encryptor.delete();
      return ciphertext;
    });

    expect(ciphertexts[0]!.length).toBeGreaterThan(frame.length);
    for (const ciphertext of ciphertexts) {
      expect(ciphertext).toEqual(ciphertexts[0]);
    }

    for (const kind of INPUT_KINDS) {
      const decryptor = new dave.Decryptor();
      decryptor.TransitionToKeyRatchet({cipherSuite: ratchet.cipherSuite, baseSecret: asInput(kind, ratchet.baseSecret)});
      expect(decrypt(decryptor, ciphertexts[0]!)).toEqual(frame);
      decryptor.delete();
    }
  });

  test.each([
    ['empty ArrayBuffer', new ArrayBuffer(0)],
    ['empty Uint8Array', new Uint8Array(0)],
    ['empty Array', []],
    ['missing', undefined],
  ])('%s baseSecret is rejected', (_, baseSecret) => {
    const keyRatchet = {cipherSuite: 2, baseSecret} as any;

    const encryptor = makeEncryptor();
    expect(() => encryptor.SetKeyRatchet(keyRatchet)).toThrow(TypeError);
    expect(encrypt(encryptor).length).toBe(0);
    encryptor.delete();

    const decryptor = new dave.Decryptor();
    expect(() => decryptor.TransitionToKeyRatchet(keyRatchet)).toThrow(TypeError);
    decryptor.delete();
  });
});
