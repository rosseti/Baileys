/**
 * passkey-flow.ts — Stateful orchestrator for the Shortcake/PassKey companion pairing protocol.
 *
 * Bridges pure crypto (shortcake.ts) and BinaryNode serialization (passkey-nodes.ts).
 * Has NO knowledge of WebSocket, ev.emit, or any I/O — the socket layer calls these methods
 * and handles the resulting nodes.
 */

import {
	initShortcakeState,
	completeShortcakeState,
	encryptPairingRequest,
} from '../Utils/shortcake'
import type { ShortcakeState, PasskeyAuthenticator, PasskeyAssertionRequest, ShortcakePairingPayload } from '../Types/Passkey'
import type { BinaryNode } from '../WABinary/types'
import {
	parsePasskeyPrologueRequest,
	buildPasskeyPrologue,
	parseCrscContinuation,
	buildEncryptedPairingRequestNode,
} from './passkey-nodes'

export interface PasskeyFlowConfig {
	authenticator?: PasskeyAuthenticator
	/** Previous ADV secret key — present only when re-linking an existing companion */
	prevAdvSecretKey?: Buffer
	/** Noise identity key pair */
	identityKey: { public: Buffer; private: Buffer }
	/** Signal signed identity key pair */
	signedIdentityKey: { public: Buffer; private: Buffer }
}

export class PasskeyFlow {
	private state: ShortcakeState | null = null
	private readonly config: PasskeyFlowConfig

	constructor(config: PasskeyFlowConfig) {
		this.config = config
	}

	/**
	 * Handle a passkey_prologue_request notification.
	 *
	 * If config.authenticator is provided, resolves the WebAuthn assertion inline and
	 * returns the <passkey_prologue> IQ immediately.
	 *
	 * If no authenticator is set, throws — the socket layer must emit the pairing.passkey-request
	 * event and call resolveAssertion() before invoking this method.
	 */
	async handlePrologueRequest(notification: BinaryNode): Promise<BinaryNode> {
		const { requestOptionsJson } = parsePasskeyPrologueRequest(notification)

		const request = this.buildAssertionRequest(requestOptionsJson)

		if(!this.config.authenticator) {
			throw new Error(
				'PasskeyFlow: no authenticator configured. ' +
				'Emit pairing.passkey-request from the socket layer and inject the assertion via resolveAssertion().'
			)
		}

		const assertion = await this.config.authenticator.getAssertion(request)

		this.state = initShortcakeState(this.config.prevAdvSecretKey)

		return buildPasskeyPrologue({
			credentialId: assertion.credentialId,
			assertionJson: assertion.assertionJson,
			ephemeralCommit: this.state.ephemeralCommit,
			handoffProof: this.state.handoffProof,
		})
	}

	/**
	 * Handle a crsc_continuation notification.
	 *
	 * Must be called after handlePrologueRequest() has set the internal state.
	 * Returns the verification code and the handoff-UX skip flag.
	 */
	handleCrscContinuation(notification: BinaryNode): { verificationCode: string; skipHandoffUx: boolean } {
		if(!this.state) {
			throw new Error('PasskeyFlow: handlePrologueRequest() must complete before handleCrscContinuation()')
		}

		const { theirEphemeralPub, skipHandoffUx } = parseCrscContinuation(notification)

		this.state = completeShortcakeState(this.state, theirEphemeralPub)

		if(!this.state.verificationCode) {
			throw new Error('PasskeyFlow: completeShortcakeState() did not produce a verification code')
		}

		return { verificationCode: this.state.verificationCode, skipHandoffUx }
	}

	/**
	 * Build the <encrypted_pairing_request> IQ.
	 *
	 * Must be called after handleCrscContinuation() has completed the DH exchange.
	 * The plaintext payload is: noiseIdentityPub ‖ signalIdentityPub ‖ rotatedAdvSecret.
	 *
	 * TODO: WIRE_FORMAT — confirm the exact plaintext layout (field order, lengths, whether
	 * protobuf-encoded vs. raw concatenation) against whatsapp-rust shortcake.rs
	 * build_encrypted_pairing_request().
	 */
	buildEncryptedPairingRequest(): BinaryNode {
		if(!this.state?.encryptionKey || !this.state.rotatedAdvSecretKey) {
			throw new Error('PasskeyFlow: DH exchange must complete before buildEncryptedPairingRequest()')
		}

		// TODO: WIRE_FORMAT — confirm plaintext layout (may need length-prefixes or protobuf)
		const plaintext = Buffer.concat([
			this.config.identityKey.public,
			this.config.signedIdentityKey.public,
			this.state.rotatedAdvSecretKey,
		])

		const payload: ShortcakePairingPayload = encryptPairingRequest(this.state.encryptionKey, plaintext)

		return buildEncryptedPairingRequestNode(payload, this.state.ephemeralKeyPair.publicKey)
	}

	/** Returns the rotated ADV secret key for persistence after pairing completes. */
	getRotatedAdvSecretKey(): Buffer {
		if(!this.state?.rotatedAdvSecretKey) {
			throw new Error('PasskeyFlow: state not initialized — call handlePrologueRequest() first')
		}

		return this.state.rotatedAdvSecretKey
	}

	/** Zero-fill sensitive key material from memory. */
	cleanup(): void {
		if(!this.state) return

		this.state.ephemeralKeyPair.privateKey.fill(0)
		this.state.ephemeralKeyPair.publicKey.fill(0)
		this.state.sharedSecret?.fill(0)
		this.state.encryptionKey?.fill(0)
		this.state.verificationKey?.fill(0)
		this.state.rotatedAdvSecretKey?.fill(0)
		this.state.handoffProof?.fill(0)
		this.state = null
	}

	// ---------------------------------------------------------------------------
	// Private helpers
	// ---------------------------------------------------------------------------

	private buildAssertionRequest(rawOptionsJson: string): PasskeyAssertionRequest {
		let parsed: Record<string, unknown> = {}
		try {
			parsed = JSON.parse(rawOptionsJson)
		} catch {
			throw new Error(`PasskeyFlow: failed to parse requestOptionsJson: ${rawOptionsJson.slice(0, 80)}`)
		}

		// TODO: WIRE_FORMAT — confirm field names in the JSON emitted by the WA server.
		// These follow the WebAuthn spec naming (PublicKeyCredentialRequestOptions).
		const challengeB64 = (parsed['challenge'] ?? '') as string
		const challenge = Buffer.from(challengeB64, 'base64')

		const allowCredentials: Buffer[] = []
		if(Array.isArray(parsed['allowCredentials'])) {
			for(const cred of parsed['allowCredentials'] as Array<{ id?: string }>) {
				if(cred.id) {
					allowCredentials.push(Buffer.from(cred.id, 'base64'))
				}
			}
		}

		return {
			challenge,
			rpId: (parsed['rpId'] as string | undefined),
			allowCredentials,
			userVerification: (parsed['userVerification'] as PasskeyAssertionRequest['userVerification']) ?? 'preferred',
			timeoutMs: (parsed['timeout'] as number | undefined),
			rawOptionsJson,
		}
	}
}
