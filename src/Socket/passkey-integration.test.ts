/**
 * Integration tests for the PassKey/Shortcake crypto round-trip.
 *
 * These tests use real crypto (no mocks of shortcake.ts or passkey-nodes.ts) to verify
 * that the companion-side flow produces an EncryptedPairingRequest that a server holding
 * the corresponding X25519 private key can decrypt and verify.
 *
 * Protocol: companion generates X25519 ephemeral key pair → sends prologue →
 *   server sends crsc_continuation with its own ephemeral pub + nonce →
 *   companion DH → encrypt PairingRequest → server DH → decrypt → verify.
 *
 * The WebAuthn assertion step is stubbed with a fixed mock (its content is opaque
 * to the Shortcake crypto layer; WA verifies it server-side only).
 */

import { randomBytes } from 'node:crypto'
import { PasskeyFlow } from './passkey-flow'
import {
	generateEphemeralKeyPair,
	deriveSharedSecret,
	deriveEncryptionKey,
	decryptPairingResponse,
} from '../Utils/shortcake'
import { proto } from '../../WAProto/index.js'
import type { BinaryNode } from '../WABinary/types'
import type { PasskeyAssertion } from '../Types/Passkey'

// ── Helpers ───────────────────────────────────────────────────────────────────

const TEST_REF     = 'test-pairing-ref-integration'
const DEVICE_TYPE  = proto.DeviceProps.PlatformType.CHROME  // default in PasskeyFlow

const MOCK_ASSERTION: PasskeyAssertion = {
	credentialId:  Buffer.from('integration-test-cred-id'),
	assertionJson: Buffer.from(JSON.stringify({
		type:              'webauthn.get',
		authenticatorData: Buffer.alloc(37).toString('base64url'),
		clientDataJSON:    Buffer.from('{"type":"webauthn.get","challenge":"test"}').toString('base64url'),
		signature:         Buffer.alloc(64).toString('base64url'),
	})),
}

/** Build a crsc_continuation BinaryNode using real server-side X25519 state. */
function buildCrscContinuation(serverPub: Buffer, serverNonce: Buffer): BinaryNode {
	const primaryEphIdentityBytes = proto.PrimaryEphemeralIdentity.encode({
		publicKey: serverPub,
		nonce:     serverNonce,
	}).finish()

	return {
		tag:     'notification',
		attrs:   { type: 'crsc_continuation', id: 'crsc-1' },
		content: [{
			tag:     'primary_ephemeral_identity',
			attrs:   {},
			content: Buffer.from(primaryEphIdentityBytes),
		}],
	}
}

/**
 * Extract the companion's ephemeral X25519 public key from a passkey_prologue IQ.
 * Path: iq → passkey_prologue → prologue_payload → ProloguePayload proto →
 *   companionEphemeralIdentity → CompanionEphemeralIdentity proto → publicKey
 */
function extractCompanionEphPub(prologueNode: BinaryNode): Buffer {
	const prologueChild = (prologueNode.content as BinaryNode[])[0]!
	const children      = prologueChild.content as BinaryNode[]
	const payloadNode   = children.find(c => c.tag === 'prologue_payload')!
	const payload       = proto.ProloguePayload.decode(payloadNode.content as Buffer)
	const ephIdentity   = proto.CompanionEphemeralIdentity.decode(
		Buffer.from(payload.companionEphemeralIdentity!)
	)
	return Buffer.from(ephIdentity.publicKey!)
}

/** Decrypt EncryptedPairingRequest bytes using the server's shared secret. */
function serverDecrypt(
	encReqBytes: Buffer,
	serverPrivateKey: Buffer,
	companionEphPub: Buffer,
): proto.IPairingRequest {
	const encReq        = proto.EncryptedPairingRequest.decode(encReqBytes)
	const sharedSecret  = deriveSharedSecret(serverPrivateKey, companionEphPub)
	const encKey        = deriveEncryptionKey(sharedSecret, DEVICE_TYPE, TEST_REF)

	const encPayload    = Buffer.from(encReq.encryptedPayload!)
	const tag           = encPayload.subarray(encPayload.length - 16)
	const ciphertext    = encPayload.subarray(0, encPayload.length - 16)
	const iv            = Buffer.from(encReq.iv!)

	const plaintext = decryptPairingResponse(encKey, { encryptedData: ciphertext, iv, tag })
	return proto.PairingRequest.decode(plaintext)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('Shortcake crypto round-trip', () => {
	it('fresh link: companion encrypts PairingRequest that server can decrypt and verify', async () => {
		// 1. Companion identity keys (in production: from authState.creds)
		const identityKey       = generateEphemeralKeyPair()
		const signedIdentityKey = generateEphemeralKeyPair()

		const flow = new PasskeyFlow({
			identityKey:       { public: identityKey.publicKey,       private: identityKey.privateKey },
			signedIdentityKey: { public: signedIdentityKey.publicKey, private: signedIdentityKey.privateKey },
		})

		// 2. Companion initializes state (equivalent to handlePrologueRequest with external assertion)
		const prologueNode = await flow.initWithExternalAssertion(
			{ tag: 'notification', attrs: {}, content: [] },
			MOCK_ASSERTION,
			TEST_REF,
		)

		// 3. Verify prologue structure
		expect(prologueNode.tag).toBe('iq')
		const prologueChild = (prologueNode.content as BinaryNode[])[0]!
		expect(prologueChild.tag).toBe('passkey_prologue')
		const children = prologueChild.content as BinaryNode[]
		expect(children.some(c => c.tag === 'credential_id')).toBe(true)
		expect(children.some(c => c.tag === 'webauthn_assertion')).toBe(true)
		expect(children.some(c => c.tag === 'prologue_payload')).toBe(true)
		expect(children.some(c => c.tag === 'pairing_handoff_proof')).toBe(false) // fresh link

		// 4. Extract companion ephemeral public key (server would get this from the prologue)
		const companionEphPub = extractCompanionEphPub(prologueNode)
		expect(companionEphPub).toHaveLength(32)

		// 5. Server generates its own ephemeral key pair and nonce
		const serverKeyPair  = generateEphemeralKeyPair()
		const serverNonce    = randomBytes(32)
		const crscNotif      = buildCrscContinuation(serverKeyPair.publicKey, serverNonce)

		// 6. Companion processes crsc_continuation
		const { verificationCode, skipHandoffUx } = flow.handleCrscContinuation(crscNotif)

		// Fresh link → no handoff proof → skipHandoffUx must be false
		expect(skipHandoffUx).toBe(false)

		// Verification code is 8 Crockford base32 chars
		expect(verificationCode).toMatch(/^[0-9A-HJKMNP-TV-Z]{8}$/)

		// 7. Build encrypted pairing request
		const pairingNode   = flow.buildEncryptedPairingRequest()
		expect(pairingNode.tag).toBe('iq')
		const encReqChild   = (pairingNode.content as BinaryNode[])[0]!
		expect(encReqChild.tag).toBe('encrypted_pairing_request')

		// 8. Server decrypts using DH(serverPriv, companionEphPub)
		const encReqBytes = Buffer.from(encReqChild.content as Buffer)
		const pairingReq  = serverDecrypt(encReqBytes, serverKeyPair.privateKey, companionEphPub)

		// 9. Verify the plaintext contains the companion's identity keys and ADV secret
		expect(Buffer.from(pairingReq.companionPublicKey!)).toEqual(identityKey.publicKey)
		expect(Buffer.from(pairingReq.companionIdentityKey!)).toEqual(signedIdentityKey.publicKey)
		expect(pairingReq.advSecret).toHaveLength(32)

		flow.cleanup()
	})

	it('re-link: handoffProof present in prologue when prevAdvSecretKey is supplied', async () => {
		const identityKey       = generateEphemeralKeyPair()
		const signedIdentityKey = generateEphemeralKeyPair()
		const prevAdvSecretKey  = randomBytes(32)

		const flow = new PasskeyFlow({
			identityKey:       { public: identityKey.publicKey,       private: identityKey.privateKey },
			signedIdentityKey: { public: signedIdentityKey.publicKey, private: signedIdentityKey.privateKey },
			prevAdvSecretKey,
		})

		const prologueNode  = await flow.initWithExternalAssertion(
			{ tag: 'notification', attrs: {}, content: [] },
			MOCK_ASSERTION,
			TEST_REF,
		)

		const children = (prologueNode.content as BinaryNode[])[0]!.content as BinaryNode[]
		expect(children.some(c => c.tag === 'pairing_handoff_proof')).toBe(true)

		const serverKeyPair = generateEphemeralKeyPair()
		const crscNotif     = buildCrscContinuation(serverKeyPair.publicKey, randomBytes(32))

		const { skipHandoffUx } = flow.handleCrscContinuation(crscNotif)

		// Re-link → handoff proof was sent → server can skip confirmation UX
		expect(skipHandoffUx).toBe(true)

		flow.cleanup()
	})

	it('rotatedAdvSecretKey differs from prevAdvSecretKey on every link', async () => {
		const prevAdvSecretKey = randomBytes(32)
		const flow = new PasskeyFlow({
			identityKey:       { public: generateEphemeralKeyPair().publicKey, private: generateEphemeralKeyPair().privateKey },
			signedIdentityKey: { public: generateEphemeralKeyPair().publicKey, private: generateEphemeralKeyPair().privateKey },
			prevAdvSecretKey,
		})

		await flow.initWithExternalAssertion(
			{ tag: 'notification', attrs: {}, content: [] },
			MOCK_ASSERTION,
			TEST_REF,
		)

		const rotated = flow.getRotatedAdvSecretKey()
		expect(rotated).toHaveLength(32)
		expect(rotated).not.toEqual(prevAdvSecretKey)

		flow.cleanup()
	})

	it('different server nonces produce different verification codes', async () => {
		const makeFlow = async () => {
			const kp   = generateEphemeralKeyPair()
			const flow = new PasskeyFlow({
				identityKey:       { public: kp.publicKey, private: kp.privateKey },
				signedIdentityKey: { public: kp.publicKey, private: kp.privateKey },
			})
			const serverKp = generateEphemeralKeyPair()
			await flow.initWithExternalAssertion(
				{ tag: 'notification', attrs: {}, content: [] },
				MOCK_ASSERTION,
				TEST_REF,
			)
			return { flow, serverKp }
		}

		const serverKp    = generateEphemeralKeyPair()
		const nonce1      = randomBytes(32)
		const nonce2      = randomBytes(32)

		const { flow: f1 } = await makeFlow()
		const { flow: f2 } = await makeFlow()

		const { verificationCode: code1 } = f1.handleCrscContinuation(buildCrscContinuation(serverKp.publicKey, nonce1))
		const { verificationCode: code2 } = f2.handleCrscContinuation(buildCrscContinuation(serverKp.publicKey, nonce2))

		expect(code1).toMatch(/^[0-9A-HJKMNP-TV-Z]{8}$/)
		expect(code2).toMatch(/^[0-9A-HJKMNP-TV-Z]{8}$/)
		// Different nonces → different codes (extremely unlikely to collide)
		expect(code1).not.toBe(code2)

		f1.cleanup()
		f2.cleanup()
	})

	it('cleanup zeroes key material and subsequent calls throw', async () => {
		const kp   = generateEphemeralKeyPair()
		const flow = new PasskeyFlow({
			identityKey:       { public: kp.publicKey, private: kp.privateKey },
			signedIdentityKey: { public: kp.publicKey, private: kp.privateKey },
		})

		await flow.initWithExternalAssertion(
			{ tag: 'notification', attrs: {}, content: [] },
			MOCK_ASSERTION,
			TEST_REF,
		)

		flow.cleanup()

		expect(() => flow.getRotatedAdvSecretKey()).toThrow()
		expect(() => flow.getCompanionNonce()).toThrow()
		expect(() => flow.buildEncryptedPairingRequest()).toThrow()
	})
})
