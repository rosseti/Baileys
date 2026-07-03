import { randomBytes } from 'node:crypto'
import {
	buildCompanionEphemeralIdentity,
	buildProloguePayload,
	completeShortcakeState,
	computeCommitmentHash,
	computeHandoffProof,
	decryptPairingResponse,
	deriveEncryptionKey,
	deriveHandoffKey,
	deriveSharedSecret,
	deriveVerificationCode,
	encryptPairingRequest,
	generateEphemeralKeyPair,
	initShortcakeState,
	rotateAdvSecretKey,
} from './shortcake'
import { proto } from '../../WAProto/index.js'

const DEVICE_TYPE = proto.DeviceProps.PlatformType.CHROME
const REF = 'test-ref-abc'

describe('generateEphemeralKeyPair', () => {
	it('returns 32-byte raw public and private keys', () => {
		const kp = generateEphemeralKeyPair()
		expect(kp.publicKey).toBeInstanceOf(Buffer)
		expect(kp.privateKey).toBeInstanceOf(Buffer)
		expect(kp.publicKey.length).toBe(32)
		expect(kp.privateKey.length).toBe(32)
	})

	it('produces different keys on each call', () => {
		const a = generateEphemeralKeyPair()
		const b = generateEphemeralKeyPair()
		expect(a.publicKey.equals(b.publicKey)).toBe(false)
	})
})

describe('buildCompanionEphemeralIdentity', () => {
	it('returns non-empty bytes containing the public key', () => {
		const { publicKey } = generateEphemeralKeyPair()
		const bytes = buildCompanionEphemeralIdentity(publicKey, DEVICE_TYPE, REF)
		expect(bytes).toBeInstanceOf(Buffer)
		expect(bytes.length).toBeGreaterThan(32)
	})

	it('is deterministic', () => {
		const { publicKey } = generateEphemeralKeyPair()
		const a = buildCompanionEphemeralIdentity(publicKey, DEVICE_TYPE, REF)
		const b = buildCompanionEphemeralIdentity(publicKey, DEVICE_TYPE, REF)
		expect(a.equals(b)).toBe(true)
	})

	it('differs for different device types', () => {
		const { publicKey } = generateEphemeralKeyPair()
		const a = buildCompanionEphemeralIdentity(publicKey, DEVICE_TYPE, REF)
		const b = buildCompanionEphemeralIdentity(publicKey, proto.DeviceProps.PlatformType.DESKTOP, REF)
		expect(a.equals(b)).toBe(false)
	})
})

describe('computeCommitmentHash', () => {
	it('returns 32 bytes', () => {
		const { publicKey } = generateEphemeralKeyPair()
		const identityBytes = buildCompanionEphemeralIdentity(publicKey, DEVICE_TYPE, REF)
		const nonce = randomBytes(32)
		const commit = computeCommitmentHash(identityBytes, nonce)
		expect(commit).toBeInstanceOf(Buffer)
		expect(commit.length).toBe(32)
	})

	it('is deterministic', () => {
		const { publicKey } = generateEphemeralKeyPair()
		const identityBytes = buildCompanionEphemeralIdentity(publicKey, DEVICE_TYPE, REF)
		const nonce = randomBytes(32)
		expect(computeCommitmentHash(identityBytes, nonce).equals(computeCommitmentHash(identityBytes, nonce))).toBe(true)
	})

	it('differs when nonce changes', () => {
		const { publicKey } = generateEphemeralKeyPair()
		const identityBytes = buildCompanionEphemeralIdentity(publicKey, DEVICE_TYPE, REF)
		const a = computeCommitmentHash(identityBytes, randomBytes(32))
		const b = computeCommitmentHash(identityBytes, randomBytes(32))
		expect(a.equals(b)).toBe(false)
	})
})

describe('buildProloguePayload', () => {
	it('returns a non-empty serialized proto', () => {
		const { publicKey } = generateEphemeralKeyPair()
		const identityBytes = buildCompanionEphemeralIdentity(publicKey, DEVICE_TYPE, REF)
		const nonce = randomBytes(32)
		const commit = computeCommitmentHash(identityBytes, nonce)
		const payload = buildProloguePayload(identityBytes, commit)
		expect(payload).toBeInstanceOf(Buffer)
		expect(payload.length).toBeGreaterThan(0)
	})
})

describe('deriveSharedSecret — Diffie-Hellman symmetry', () => {
	it('Alice and Bob derive the same shared secret', () => {
		const alice = generateEphemeralKeyPair()
		const bob = generateEphemeralKeyPair()

		const aliceSecret = deriveSharedSecret(alice.privateKey, bob.publicKey)
		const bobSecret = deriveSharedSecret(bob.privateKey, alice.publicKey)

		expect(aliceSecret.length).toBe(32)
		expect(aliceSecret.equals(bobSecret)).toBe(true)
	})
})

describe('deriveEncryptionKey', () => {
	it('returns 32 bytes', () => {
		const secret = randomBytes(32)
		const key = deriveEncryptionKey(secret, DEVICE_TYPE, REF)
		expect(key).toBeInstanceOf(Buffer)
		expect(key.length).toBe(32)
	})

	it('differs for different device types', () => {
		const secret = randomBytes(32)
		const a = deriveEncryptionKey(secret, proto.DeviceProps.PlatformType.CHROME, REF)
		const b = deriveEncryptionKey(secret, proto.DeviceProps.PlatformType.DESKTOP, REF)
		expect(a.equals(b)).toBe(false)
	})

	it('differs for different ref strings', () => {
		const secret = randomBytes(32)
		const a = deriveEncryptionKey(secret, DEVICE_TYPE, 'ref-a')
		const b = deriveEncryptionKey(secret, DEVICE_TYPE, 'ref-b')
		expect(a.equals(b)).toBe(false)
	})

	it('companion and primary derive the same key from a DH exchange', () => {
		const companion = generateEphemeralKeyPair()
		const primary = generateEphemeralKeyPair()

		const companionKey = deriveEncryptionKey(
			deriveSharedSecret(companion.privateKey, primary.publicKey), DEVICE_TYPE, REF
		)
		const primaryKey = deriveEncryptionKey(
			deriveSharedSecret(primary.privateKey, companion.publicKey), DEVICE_TYPE, REF
		)

		expect(companionKey.equals(primaryKey)).toBe(true)
	})
})

describe('deriveVerificationCode', () => {
	it('returns exactly 8 Crockford base32 characters', () => {
		const companionNonce = randomBytes(32)
		const primaryPub = generateEphemeralKeyPair().publicKey
		const primaryNonce = randomBytes(32)
		const code = deriveVerificationCode(companionNonce, primaryPub, primaryNonce)
		expect(code).toHaveLength(8)
		expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{8}$/)
	})

	it('is deterministic', () => {
		const companionNonce = randomBytes(32)
		const primaryPub = generateEphemeralKeyPair().publicKey
		const primaryNonce = randomBytes(32)
		expect(deriveVerificationCode(companionNonce, primaryPub, primaryNonce))
			.toBe(deriveVerificationCode(companionNonce, primaryPub, primaryNonce))
	})

	it('differs when any input changes', () => {
		const cn = randomBytes(32)
		const pub = generateEphemeralKeyPair().publicKey
		const pn = randomBytes(32)
		const base = deriveVerificationCode(cn, pub, pn)
		expect(deriveVerificationCode(randomBytes(32), pub, pn)).not.toBe(base)
		expect(deriveVerificationCode(cn, generateEphemeralKeyPair().publicKey, pn)).not.toBe(base)
		expect(deriveVerificationCode(cn, pub, randomBytes(32))).not.toBe(base)
	})
})

describe('deriveHandoffKey + computeHandoffProof', () => {
	it('handoff key is 32 bytes', () => {
		const prevAdv = rotateAdvSecretKey()
		const key = deriveHandoffKey(prevAdv)
		expect(key).toBeInstanceOf(Buffer)
		expect(key.length).toBe(32)
	})

	it('handoff proof is a 32-byte HMAC over the prologue payload', () => {
		const prevAdv = rotateAdvSecretKey()
		const handoffKey = deriveHandoffKey(prevAdv)
		const prologuePayload = randomBytes(64)
		const proof = computeHandoffProof(handoffKey, prologuePayload)
		expect(proof).toBeInstanceOf(Buffer)
		expect(proof.length).toBe(32)
	})

	it('different prologue payloads → different proofs', () => {
		const handoffKey = deriveHandoffKey(rotateAdvSecretKey())
		const a = computeHandoffProof(handoffKey, randomBytes(64))
		const b = computeHandoffProof(handoffKey, randomBytes(64))
		expect(a.equals(b)).toBe(false)
	})
})

describe('rotateAdvSecretKey', () => {
	it('returns 32 random bytes', () => {
		const key = rotateAdvSecretKey()
		expect(key).toBeInstanceOf(Buffer)
		expect(key.length).toBe(32)
	})

	it('is different on each call', () => {
		expect(rotateAdvSecretKey().equals(rotateAdvSecretKey())).toBe(false)
	})
})

describe('encryptPairingRequest / decryptPairingResponse', () => {
	it('round-trip returns original plaintext', () => {
		const key = deriveEncryptionKey(randomBytes(32), DEVICE_TYPE, REF)
		const plaintext = Buffer.from('hello shortcake world')
		const payload = encryptPairingRequest(key, plaintext)

		expect(payload.iv.length).toBe(12)
		expect(payload.tag.length).toBe(16)
		expect(payload.encryptedData.equals(plaintext)).toBe(false)

		const decrypted = decryptPairingResponse(key, payload)
		expect(decrypted.equals(plaintext)).toBe(true)
	})

	it('rejects tampered ciphertext', () => {
		const key = deriveEncryptionKey(randomBytes(32), DEVICE_TYPE, REF)
		const payload = encryptPairingRequest(key, Buffer.from('secret'))
		payload.encryptedData.writeUInt8(payload.encryptedData.readUInt8(0) ^ 0xff, 0)
		expect(() => decryptPairingResponse(key, payload)).toThrow()
	})

	it('produces different IVs on each encrypt call', () => {
		const key = deriveEncryptionKey(randomBytes(32), DEVICE_TYPE, REF)
		const p1 = encryptPairingRequest(key, Buffer.from('data'))
		const p2 = encryptPairingRequest(key, Buffer.from('data'))
		expect(p1.iv.equals(p2.iv)).toBe(false)
	})
})

describe('initShortcakeState', () => {
	it('without prevAdvSecretKey — handoffProof is undefined', () => {
		const state = initShortcakeState(DEVICE_TYPE, REF)
		expect(state.ephemeralKeyPair.publicKey.length).toBe(32)
		expect(state.companionNonce.length).toBe(32)
		expect(state.ephemeralCommit.length).toBe(32)
		expect(state.prologuePayloadBytes.length).toBeGreaterThan(0)
		expect(state.rotatedAdvSecretKey.length).toBe(32)
		expect(state.handoffProof).toBeUndefined()
		expect(state.sharedSecret).toBeUndefined()
		expect(state.encryptionKey).toBeUndefined()
		expect(state.verificationCode).toBeUndefined()
	})

	it('with prevAdvSecretKey — handoffProof is a 32-byte Buffer', () => {
		const prevAdv = rotateAdvSecretKey()
		const state = initShortcakeState(DEVICE_TYPE, REF, prevAdv)
		expect(state.handoffProof).toBeInstanceOf(Buffer)
		expect(state.handoffProof!.length).toBe(32)
	})

	it('ephemeralCommit equals SHA-256(identityBytes || nonce)', () => {
		const state = initShortcakeState(DEVICE_TYPE, REF)
		const expected = computeCommitmentHash(state.companionEphemeralIdentityBytes, state.companionNonce)
		expect(state.ephemeralCommit.equals(expected)).toBe(true)
	})
})

describe('completeShortcakeState', () => {
	it('companion and primary derive the same encryption key', () => {
		const companionState = initShortcakeState(DEVICE_TYPE, REF)
		const primaryKp = generateEphemeralKeyPair()
		const primaryNonce = randomBytes(32)

		const completed = completeShortcakeState(companionState, primaryKp.publicKey, primaryNonce)

		// Primary's side: raw DH then HKDF with same salt
		const primaryEncKey = deriveEncryptionKey(
			deriveSharedSecret(primaryKp.privateKey, companionState.ephemeralKeyPair.publicKey),
			DEVICE_TYPE,
			REF,
		)

		expect(completed.encryptionKey!.equals(primaryEncKey)).toBe(true)
	})

	it('verification code is 8 Crockford chars', () => {
		const companionState = initShortcakeState(DEVICE_TYPE, REF)
		const primaryKp = generateEphemeralKeyPair()
		const primaryNonce = randomBytes(32)

		const completed = completeShortcakeState(companionState, primaryKp.publicKey, primaryNonce)
		expect(completed.verificationCode).toMatch(/^[0-9A-HJKMNP-TV-Z]{8}$/)
	})

	it('preserves original state fields', () => {
		const state = initShortcakeState(DEVICE_TYPE, REF)
		const primaryKp = generateEphemeralKeyPair()
		const completed = completeShortcakeState(state, primaryKp.publicKey, randomBytes(32))

		expect(completed.ephemeralKeyPair).toBe(state.ephemeralKeyPair)
		expect(completed.ephemeralCommit.equals(state.ephemeralCommit)).toBe(true)
		expect(completed.rotatedAdvSecretKey.equals(state.rotatedAdvSecretKey)).toBe(true)
	})
})
