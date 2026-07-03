import {
	completeShortcakeState,
	computeCommit,
	computeHandoffProof,
	decryptPairingResponse,
	deriveKeys,
	deriveSharedSecret,
	encryptPairingRequest,
	formatVerificationCode,
	generateEphemeralKeyPair,
	initShortcakeState,
	rotateAdvSecretKey,
} from './shortcake'

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

describe('computeCommit', () => {
	it('returns a 32-byte SHA-256 of the public key', () => {
		const { publicKey } = generateEphemeralKeyPair()
		const commit = computeCommit(publicKey)
		expect(commit).toBeInstanceOf(Buffer)
		expect(commit.length).toBe(32)
	})

	it('is deterministic', () => {
		const { publicKey } = generateEphemeralKeyPair()
		expect(computeCommit(publicKey).equals(computeCommit(publicKey))).toBe(true)
	})

	it('differs for different public keys', () => {
		const a = generateEphemeralKeyPair()
		const b = generateEphemeralKeyPair()
		expect(computeCommit(a.publicKey).equals(computeCommit(b.publicKey))).toBe(false)
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

describe('deriveKeys', () => {
	it('returns two independent 32-byte keys', () => {
		const { publicKey } = generateEphemeralKeyPair()
		const { encryptionKey, verificationKey } = deriveKeys(publicKey)
		expect(encryptionKey.length).toBe(32)
		expect(verificationKey.length).toBe(32)
		expect(encryptionKey.equals(verificationKey)).toBe(false)
	})

	it('accepts an optional info buffer', () => {
		const secret = generateEphemeralKeyPair().publicKey
		const { encryptionKey: k1 } = deriveKeys(secret)
		const { encryptionKey: k2 } = deriveKeys(secret, Buffer.from('custom_info'))
		expect(k1.equals(k2)).toBe(false)
	})
})

describe('formatVerificationCode', () => {
	it('matches the DDDD-DDDD pattern', () => {
		const { verificationKey } = deriveKeys(generateEphemeralKeyPair().publicKey)
		const code = formatVerificationCode(verificationKey)
		expect(code).toMatch(/^\d{4}-\d{4}$/)
	})

	it('is deterministic for the same input', () => {
		const { verificationKey } = deriveKeys(generateEphemeralKeyPair().publicKey)
		expect(formatVerificationCode(verificationKey)).toBe(formatVerificationCode(verificationKey))
	})
})

describe('computeHandoffProof', () => {
	it('returns a 32-byte HMAC', () => {
		const prevAdv = rotateAdvSecretKey()
		const context = generateEphemeralKeyPair().publicKey
		const proof = computeHandoffProof(prevAdv, context)
		expect(proof).toBeInstanceOf(Buffer)
		expect(proof.length).toBe(32)
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
		const { encryptionKey } = deriveKeys(generateEphemeralKeyPair().publicKey)
		const plaintext = Buffer.from('hello shortcake world')
		const payload = encryptPairingRequest(encryptionKey, plaintext)

		expect(payload.iv.length).toBe(12)
		expect(payload.tag.length).toBe(16)
		expect(payload.encryptedData.equals(plaintext)).toBe(false)

		const decrypted = decryptPairingResponse(encryptionKey, payload)
		expect(decrypted.equals(plaintext)).toBe(true)
	})

	it('rejects tampered ciphertext', () => {
		const { encryptionKey } = deriveKeys(generateEphemeralKeyPair().publicKey)
		const payload = encryptPairingRequest(encryptionKey, Buffer.from('secret'))
		payload.encryptedData.writeUInt8(payload.encryptedData.readUInt8(0) ^ 0xff, 0)
		expect(() => decryptPairingResponse(encryptionKey, payload)).toThrow()
	})

	it('produces different IVs on each encrypt call', () => {
		const { encryptionKey } = deriveKeys(generateEphemeralKeyPair().publicKey)
		const p1 = encryptPairingRequest(encryptionKey, Buffer.from('data'))
		const p2 = encryptPairingRequest(encryptionKey, Buffer.from('data'))
		expect(p1.iv.equals(p2.iv)).toBe(false)
	})
})

describe('initShortcakeState', () => {
	it('without prevAdvSecretKey — handoffProof is undefined', () => {
		const state = initShortcakeState()
		expect(state.ephemeralKeyPair.publicKey.length).toBe(32)
		expect(state.ephemeralCommit.length).toBe(32)
		expect(state.rotatedAdvSecretKey!.length).toBe(32)
		expect(state.handoffProof).toBeUndefined()
		// partial state — shared secret not yet derived
		expect(state.sharedSecret).toBeUndefined()
		expect(state.encryptionKey).toBeUndefined()
		expect(state.verificationCode).toBeUndefined()
	})

	it('with prevAdvSecretKey — handoffProof is a 32-byte Buffer', () => {
		const prevAdv = rotateAdvSecretKey()
		const state = initShortcakeState(prevAdv)
		expect(state.handoffProof).toBeInstanceOf(Buffer)
		expect(state.handoffProof!.length).toBe(32)
	})

	it('commit equals SHA-256 of ephemeral public key', () => {
		const state = initShortcakeState()
		const expected = computeCommit(state.ephemeralKeyPair.publicKey)
		expect(state.ephemeralCommit.equals(expected)).toBe(true)
	})
})

describe('completeShortcakeState', () => {
	it('produces a non-empty verificationCode in DDDD-DDDD format', () => {
		const alice = initShortcakeState()
		const bob = initShortcakeState()

		const aliceComplete = completeShortcakeState(alice, bob.ephemeralKeyPair.publicKey)
		const bobComplete = completeShortcakeState(bob, alice.ephemeralKeyPair.publicKey)

		expect(aliceComplete.verificationCode).toMatch(/^\d{4}-\d{4}$/)
		expect(aliceComplete.verificationCode).toBe(bobComplete.verificationCode)
	})

	it('Alice and Bob derive the same encryption key', () => {
		const alice = initShortcakeState()
		const bob = initShortcakeState()

		const aliceComplete = completeShortcakeState(alice, bob.ephemeralKeyPair.publicKey)
		const bobComplete = completeShortcakeState(bob, alice.ephemeralKeyPair.publicKey)

		expect(aliceComplete.encryptionKey!.equals(bobComplete.encryptionKey!)).toBe(true)
	})

	it('preserves original state fields', () => {
		const state = initShortcakeState()
		const peer = generateEphemeralKeyPair()
		const completed = completeShortcakeState(state, peer.publicKey)

		expect(completed.ephemeralKeyPair).toBe(state.ephemeralKeyPair)
		expect(completed.ephemeralCommit.equals(state.ephemeralCommit)).toBe(true)
		expect(completed.rotatedAdvSecretKey?.equals(state.rotatedAdvSecretKey!)).toBe(true)
	})
})
