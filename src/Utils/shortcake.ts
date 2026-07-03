/**
 * Shortcake — pure crypto module for PassKey/Shortcake companion pairing.
 *
 * Zero I/O, zero side effects. All state flows through function arguments and return values.
 * Depends only on node:crypto, the hkdf re-export from ./crypto, and WAProto for protobuf encoding.
 *
 * Protocol reference: https://whatsapp-rust.jlucaso.com/concepts/authentication#companionwebclienttype
 * Verified against: oxidezap/whatsapp-rust wacore/src/shortcake.rs
 */

import {
	createCipheriv,
	createDecipheriv,
	createHash,
	createHmac,
	createPrivateKey,
	createPublicKey,
	diffieHellman,
	generateKeyPairSync,
	randomBytes,
} from 'node:crypto'
import { hkdf } from './crypto'
import { proto } from '../../WAProto/index.js'
import type { ShortcakeState, ShortcakePairingPayload } from '../Types/Passkey'

// X25519 DER headers (fixed ASN.1 wrappers for raw 32-byte keys)
const SPKI_HEADER = Buffer.from('302a300506032b656e032100', 'hex')   // 12 bytes → raw pub
const PKCS8_HEADER = Buffer.from('302e020100300506032b656e04220420', 'hex') // 16 bytes → raw priv

// HKDF constants (confirmed against oxidezap/whatsapp-rust shortcake.rs)
const HANDOFF_INFO = 'shortcake-passkey-handoff-v1'
const ENC_KEY_INFO = 'Pairing Information Encryption Key'

// Crockford base32 alphabet (RFC 4648 variant without I, L, O, U)
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'

/** Encodes exactly 5 bytes → 8 Crockford base32 characters. */
function encodeCrockford(bytes: Buffer): string {
	// 5 bytes = 40 bits; 40 / 5 = 8 characters
	let bits = 0
	let result = ''
	for(const byte of bytes) {
		bits = (bits << 8) | byte
	}
	for(let shift = 35; shift >= 0; shift -= 5) {
		result += CROCKFORD[(bits >> shift) & 0x1f]!
	}
	return result
}

export function generateEphemeralKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
	const { publicKey, privateKey } = generateKeyPairSync('x25519')
	const rawPub = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).subarray(SPKI_HEADER.length)
	const rawPriv = Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' })).subarray(PKCS8_HEADER.length)
	return { publicKey: rawPub, privateKey: rawPriv }
}

/**
 * Builds the serialized CompanionEphemeralIdentity proto.
 * This proto binds the companion's ephemeral X25519 public key to its device type and ref string.
 * The resulting bytes are the input to commitmentHash and prologuePayload.
 */
export function buildCompanionEphemeralIdentity(
	publicKey: Buffer,
	deviceType: proto.DeviceProps.PlatformType,
	ref: string,
): Buffer {
	return Buffer.from(
		proto.CompanionEphemeralIdentity.encode({ publicKey, deviceType, ref }).finish()
	)
}

/**
 * Builds the serialized ProloguePayload proto.
 * Used as the HMAC input for handoffProof (re-link flows).
 */
export function buildProloguePayload(
	companionEphemeralIdentityBytes: Buffer,
	commitmentHash: Buffer,
): Buffer {
	return Buffer.from(
		proto.ProloguePayload.encode({
			companionEphemeralIdentity: companionEphemeralIdentityBytes,
			commitment: proto.CompanionCommitment.create({ hash: commitmentHash }),
		}).finish()
	)
}

/**
 * SHA-256(companionEphemeralIdentityBytes || companionNonce).
 * Commits the companion to its ephemeral identity without revealing the nonce.
 */
export function computeCommitmentHash(
	companionEphemeralIdentityBytes: Buffer,
	companionNonce: Buffer,
): Buffer {
	return createHash('sha256')
		.update(companionEphemeralIdentityBytes)
		.update(companionNonce)
		.digest()
}

export function deriveSharedSecret(myPrivate: Buffer, theirPublic: Buffer): Buffer {
	const privKey = createPrivateKey({
		key: Buffer.concat([PKCS8_HEADER, myPrivate]),
		format: 'der',
		type: 'pkcs8',
	})
	const pubKey = createPublicKey({
		key: Buffer.concat([SPKI_HEADER, theirPublic]),
		format: 'der',
		type: 'spki',
	})
	return Buffer.from(diffieHellman({ privateKey: privKey, publicKey: pubKey }))
}

/**
 * Derives the 32-byte AES-256-GCM encryption key from the X25519 shared secret.
 *
 * Salt: "Companion Pairing {deviceType} with ref {ref}"  (human-readable, dynamic)
 * Info: "Pairing Information Encryption Key"
 */
export function deriveEncryptionKey(
	sharedSecret: Buffer,
	deviceType: number,
	ref: string,
): Buffer {
	const salt = Buffer.from(`Companion Pairing ${deviceType} with ref ${ref}`)
	return Buffer.from(hkdf(sharedSecret, 32, { salt, info: ENC_KEY_INFO }))
}

/**
 * Derives the HMAC key used to prove continuity with a previous ADV secret.
 *
 * IKM: prevAdvSecretKey, salt: none, info: "shortcake-passkey-handoff-v1"
 */
export function deriveHandoffKey(prevAdvSecretKey: Buffer): Buffer {
	return Buffer.from(hkdf(prevAdvSecretKey, 32, { info: HANDOFF_INFO }))
}

/**
 * HMAC-SHA256(handoffKey, prologuePayloadBytes).
 * Proves continuity with the previous ADV secret without replacing the WebAuthn assertion.
 * The handoffKey must be derived via deriveHandoffKey() before calling this.
 */
export function computeHandoffProof(handoffKey: Buffer, prologuePayloadBytes: Buffer): Buffer {
	return createHmac('sha256', handoffKey).update(prologuePayloadBytes).digest()
}

/**
 * Derives the 8-character Crockford base32 verification code.
 *
 * digest = SHA-256(companionNonce || primaryPublicKey)
 * code   = Crockford-base32( primaryNonce[0..5] XOR digest[0..5] )
 */
export function deriveVerificationCode(
	companionNonce: Buffer,
	primaryPublicKey: Buffer,
	primaryNonce: Buffer,
): string {
	const digest = createHash('sha256')
		.update(companionNonce)
		.update(primaryPublicKey)
		.digest()

	const xored = Buffer.allocUnsafe(5)
	for(let i = 0; i < 5; i++) {
		xored[i] = primaryNonce[i]! ^ digest[i]!
	}
	return encodeCrockford(xored)
}

export function rotateAdvSecretKey(): Buffer {
	return randomBytes(32)
}

export function encryptPairingRequest(
	encryptionKey: Buffer,
	plaintext: Buffer
): ShortcakePairingPayload {
	const iv = randomBytes(12)
	const cipher = createCipheriv('aes-256-gcm', encryptionKey, iv)
	const encryptedData = Buffer.concat([cipher.update(plaintext), cipher.final()])
	const tag = cipher.getAuthTag()
	return { encryptedData, iv, tag }
}

export function decryptPairingResponse(
	encryptionKey: Buffer,
	payload: ShortcakePairingPayload
): Buffer {
	const decipher = createDecipheriv('aes-256-gcm', encryptionKey, payload.iv)
	decipher.setAuthTag(payload.tag)
	return Buffer.concat([decipher.update(payload.encryptedData), decipher.final()])
}

/**
 * Initializes all companion-side state for one Shortcake pairing attempt.
 *
 * Generates ephemeral key pair and companion nonce, builds and commits the
 * CompanionEphemeralIdentity and ProloguePayload protos, and — when relinking —
 * derives and computes the handoff proof.
 */
export function initShortcakeState(
	deviceType: proto.DeviceProps.PlatformType,
	ref: string,
	prevAdvSecretKey?: Buffer,
): ShortcakeState {
	const ephemeralKeyPair = generateEphemeralKeyPair()
	const companionNonce = randomBytes(32)
	const companionEphemeralIdentityBytes = buildCompanionEphemeralIdentity(
		ephemeralKeyPair.publicKey,
		deviceType,
		ref,
	)
	const ephemeralCommit = computeCommitmentHash(companionEphemeralIdentityBytes, companionNonce)
	const prologuePayloadBytes = buildProloguePayload(companionEphemeralIdentityBytes, ephemeralCommit)
	const rotatedAdvSecretKey = rotateAdvSecretKey()

	const state: ShortcakeState = {
		ephemeralKeyPair,
		companionNonce,
		companionEphemeralIdentityBytes,
		ephemeralCommit,
		prologuePayloadBytes,
		deviceType,
		ref,
		rotatedAdvSecretKey,
	}

	if(prevAdvSecretKey) {
		const handoffKey = deriveHandoffKey(prevAdvSecretKey)
		state.handoffProof = computeHandoffProof(handoffKey, prologuePayloadBytes)
	}

	return state
}

/**
 * Completes the Shortcake state after receiving the server's crsc_continuation.
 *
 * Performs X25519 DH, derives the encryption key, and derives the verification code.
 */
export function completeShortcakeState(
	state: ShortcakeState,
	primaryPublicKey: Buffer,
	primaryNonce: Buffer,
): ShortcakeState {
	const sharedSecret = deriveSharedSecret(state.ephemeralKeyPair.privateKey, primaryPublicKey)
	const encryptionKey = deriveEncryptionKey(sharedSecret, state.deviceType, state.ref)
	const verificationCode = deriveVerificationCode(state.companionNonce, primaryPublicKey, primaryNonce)

	return {
		...state,
		primaryPublicKey,
		primaryNonce,
		sharedSecret,
		encryptionKey,
		verificationCode,
	}
}
