/**
 * Shortcake — pure crypto module for PassKey/Shortcake companion pairing.
 *
 * Zero I/O, zero side effects. All state flows through function arguments and return values.
 * Depends only on node:crypto and the hkdf re-export from ./crypto (whatsapp-rust-bridge).
 *
 * Protocol reference: https://whatsapp-rust.jlucaso.com/concepts/authentication#companionwebclienttype
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
import type { ShortcakePairingPayload, ShortcakeState } from '../Types/Passkey'

// X25519 DER headers (fixed ASN.1 wrappers for raw 32-byte keys)
const SPKI_HEADER = Buffer.from('302a300506032b656e032100', 'hex')   // 12 bytes → raw pub
const PKCS8_HEADER = Buffer.from('302e020100300506032b656e04220420', 'hex') // 16 bytes → raw priv

// TODO: WIRE_FORMAT — confirm the exact info string used by WhatsApp for shortcake key derivation
const HKDF_INFO_KEYS = 'shortcake_keys'

// TODO: WIRE_FORMAT — confirm verification code derivation (truncation vs. separate HKDF output)
const HKDF_INFO_VER = 'shortcake_ver'

export function generateEphemeralKeyPair(): { publicKey: Buffer; privateKey: Buffer } {
	const { publicKey, privateKey } = generateKeyPairSync('x25519')
	const rawPub = Buffer.from(publicKey.export({ type: 'spki', format: 'der' })).subarray(SPKI_HEADER.length)
	const rawPriv = Buffer.from(privateKey.export({ type: 'pkcs8', format: 'der' })).subarray(PKCS8_HEADER.length)
	return { publicKey: rawPub, privateKey: rawPriv }
}

export function computeCommit(ephemeralPub: Buffer): Buffer {
	return createHash('sha256').update(ephemeralPub).digest()
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
	// TODO: WIRE_FORMAT — confirm whether WhatsApp applies any post-processing to the raw DH output
	return Buffer.from(diffieHellman({ privateKey: privKey, publicKey: pubKey }))
}

export function deriveKeys(
	sharedSecret: Buffer,
	info?: Buffer
): { encryptionKey: Buffer; verificationKey: Buffer } {
	// TODO: WIRE_FORMAT — confirm salt (empty vs. zeros vs. commit value)
	const infoStr = info ? info.toString('latin1') : HKDF_INFO_KEYS
	const derived = Buffer.from(hkdf(sharedSecret, 64, { info: infoStr }))
	return {
		encryptionKey: derived.subarray(0, 32),
		verificationKey: derived.subarray(32, 64),
	}
}

export function formatVerificationCode(verificationKey: Buffer): string {
	// TODO: WIRE_FORMAT — confirm exact algorithm (direct truncation vs. HKDF sub-derivation)
	// Current: take first 8 bytes of a dedicated HKDF derivation, interpret as two 4-digit decimal groups
	const raw = Buffer.from(hkdf(verificationKey, 8, { info: HKDF_INFO_VER }))
	const hi = raw.readUInt32BE(0) % 10000
	const lo = raw.readUInt32BE(4) % 10000
	return `${hi.toString().padStart(4, '0')}-${lo.toString().padStart(4, '0')}`
}

export function computeHandoffProof(prevAdvSecretKey: Buffer, context: Buffer): Buffer {
	// TODO: WIRE_FORMAT — confirm what "context" is (likely ephemeral pub or commit)
	return createHmac('sha256', prevAdvSecretKey).update(context).digest()
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

export function initShortcakeState(prevAdvSecretKey?: Buffer): ShortcakeState {
	const ephemeralKeyPair = generateEphemeralKeyPair()
	const ephemeralCommit = computeCommit(ephemeralKeyPair.publicKey)
	const rotatedAdvSecretKey = rotateAdvSecretKey()

	const state: ShortcakeState = {
		ephemeralKeyPair,
		ephemeralCommit,
		rotatedAdvSecretKey,
	}

	if(prevAdvSecretKey) {
		// TODO: WIRE_FORMAT — confirm handoff context (ephemeral pub? commit? rotated key?)
		state.handoffProof = computeHandoffProof(prevAdvSecretKey, ephemeralKeyPair.publicKey)
	}

	return state
}

export function completeShortcakeState(
	state: ShortcakeState,
	theirEphemeralPub: Buffer
): ShortcakeState {
	const sharedSecret = deriveSharedSecret(state.ephemeralKeyPair.privateKey, theirEphemeralPub)
	const { encryptionKey, verificationKey } = deriveKeys(sharedSecret)
	const verificationCode = formatVerificationCode(verificationKey)

	return {
		...state,
		theirEphemeralPub,
		sharedSecret,
		encryptionKey,
		verificationKey,
		verificationCode,
	}
}
