/**
 * Types for PassKey/Shortcake companion pairing (third pairing method after QR and Pair Code).
 *
 * Protocol reference: https://whatsapp-rust.jlucaso.com/concepts/authentication#companionwebclienttype
 *
 * TODO: integrate PasskeyEvents into BaileysEventMap (Events.ts line 20 — add union entries after 'connection.update').
 */

/** Request arriving from WA Server via passkey_prologue_request */
export interface PasskeyAssertionRequest {
	challenge: Buffer
	rpId?: string
	allowCredentials: Buffer[]
	userVerification: 'required' | 'preferred' | 'discouraged'
	timeoutMs?: number
	/** Verbatim JSON from the server, forwarded to the authenticator */
	rawOptionsJson: string
}

/** Resolved WebAuthn assertion returned by the consumer's authenticator */
export interface PasskeyAssertion {
	/** JSON in the shape WA expects inside <webauthn_assertion> */
	assertionJson: Buffer
	credentialId: Buffer
}

/** Consumer-implemented interface for resolving WebAuthn assertions */
export interface PasskeyAuthenticator {
	getAssertion(request: PasskeyAssertionRequest): Promise<PasskeyAssertion>
}

/** Ephemeral state during the Shortcake flow — lives in memory, never persisted */
export interface ShortcakeState {
	ephemeralKeyPair: { publicKey: Buffer; privateKey: Buffer }
	/** SHA-256 of ephemeralKeyPair.publicKey */
	ephemeralCommit: Buffer
	/** Received via crsc_continuation from the server */
	theirEphemeralPub?: Buffer
	/** X25519 DH result */
	sharedSecret?: Buffer
	/** Derived from sharedSecret via HKDF */
	encryptionKey?: Buffer
	/** Derived from sharedSecret via HKDF, used for verification code generation */
	verificationKey?: Buffer
	/** Human-readable code shown to the user, format "DDDD-DDDD" */
	verificationCode?: string
	/** New ADV secret for this pairing session */
	rotatedAdvSecretKey?: Buffer
	/** HMAC-SHA256 of the previous ADV secret — used for re-link / handoff */
	handoffProof?: Buffer
}

/** Final payload ready for encrypted_pairing_request */
export interface ShortcakePairingPayload {
	encryptedData: Buffer
	iv: Buffer
	tag: Buffer
}

/** Parameters for constructing the passkey_prologue IQ node */
export interface PasskeyPrologueParams {
	credentialId: Buffer
	assertionJson: Buffer
	ephemeralCommit: Buffer
	handoffProof?: Buffer
}

/** Data extracted from a crsc_continuation notification */
export interface CrscContinuationData {
	theirEphemeralPub: Buffer
	skipHandoffUx: boolean
}

/** New events emitted during the Shortcake/PassKey pairing flow.
 *
 * TODO: merge into BaileysEventMap in src/Types/Events.ts by adding:
 *   'pairing.passkey-request': PasskeyEvents['pairing.passkey-request']
 *   'pairing.passkey-confirmation': PasskeyEvents['pairing.passkey-confirmation']
 *   'pairing.passkey-error': PasskeyEvents['pairing.passkey-error']
 */
export type PasskeyEvents = {
	'pairing.passkey-request': { requestOptionsJson: string; deviceId: string }
	'pairing.passkey-confirmation': { code: string; skipHandoffUx: boolean }
	'pairing.passkey-error': { error: string; isContinuable: boolean }
}
