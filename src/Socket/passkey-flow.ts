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
import { proto } from '../../WAProto/index.js'
import type { ShortcakeState, PasskeyAuthenticator, PasskeyAssertionRequest, PasskeyAssertion, ShortcakePairingPayload } from '../Types/Passkey'
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
	/**
	 * Device platform type baked into the HKDF salt.
	 * Defaults to CHROME (1) for web companions.
	 */
	deviceType?: proto.DeviceProps.PlatformType
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
	 * pairingRef must be fetched from the server via buildRefQuery() before calling this.
	 * optionsJson may be passed in if already available (inline in the notification);
	 * if omitted, it is extracted from the notification's <passkey_request_options> child.
	 *
	 * If config.authenticator is provided, resolves the WebAuthn assertion inline and
	 * returns the <passkey_prologue> IQ immediately.
	 */
	async handlePrologueRequest(
		notification: BinaryNode,
		pairingRef: string,
		optionsJson?: string,
	): Promise<BinaryNode> {
		const json = optionsJson ?? parsePasskeyPrologueRequest(notification).requestOptionsJson
		if(!json) {
			throw new Error('PasskeyFlow: passkey_request_options unavailable — fetch via buildRequestOptionsQuery()')
		}

		const request = this.buildAssertionRequest(json)

		if(!this.config.authenticator) {
			throw new Error(
				'PasskeyFlow: no authenticator configured. ' +
				'Emit pairing.passkey-request from the socket layer and inject the assertion via initWithExternalAssertion().'
			)
		}

		const assertion = await this.config.authenticator.getAssertion(request)

		const deviceType = this.config.deviceType ?? proto.DeviceProps.PlatformType.CHROME
		this.state = initShortcakeState(deviceType, pairingRef, this.config.prevAdvSecretKey)

		return buildPasskeyPrologue({
			credentialId: assertion.credentialId,
			assertionJson: assertion.assertionJson,
			prologuePayloadBytes: this.state.prologuePayloadBytes,
			handoffProof: this.state.handoffProof,
		})
	}

	/**
	 * Handle a crsc_continuation notification.
	 *
	 * Must be called after handlePrologueRequest() has set the internal state.
	 * Returns the verification code and the handoff-UX skip flag.
	 *
	 * skipHandoffUx is computed locally: true when a pairing_handoff_proof was
	 * included in the prologue (re-link path), not received from the server.
	 */
	handleCrscContinuation(notification: BinaryNode): { verificationCode: string; skipHandoffUx: boolean } {
		if(!this.state) {
			throw new Error('PasskeyFlow: handlePrologueRequest() must complete before handleCrscContinuation()')
		}

		const { primaryPublicKey, primaryNonce } = parseCrscContinuation(notification)
		const skipHandoffUx = this.state.handoffProof !== undefined

		this.state = completeShortcakeState(this.state, primaryPublicKey, primaryNonce)

		if(!this.state.verificationCode) {
			throw new Error('PasskeyFlow: completeShortcakeState() did not produce a verification code')
		}

		return { verificationCode: this.state.verificationCode, skipHandoffUx }
	}

	/**
	 * Returns the companion nonce for the <companion_nonce> IQ that must be sent
	 * after crsc_continuation and before buildEncryptedPairingRequest().
	 */
	getCompanionNonce(): Buffer {
		if(!this.state?.companionNonce) {
			throw new Error('PasskeyFlow: state not initialized — call handlePrologueRequest() first')
		}
		return this.state.companionNonce
	}

	/**
	 * Build the <encrypted_pairing_request> IQ.
	 *
	 * Must be called after handleCrscContinuation() has completed the DH exchange,
	 * and after the companion_nonce IQ has been sent.
	 * Plaintext is a protobuf-encoded PairingRequest:
	 *   { companionPublicKey: noiseIdentityPub, companionIdentityKey: signalIdentityPub, advSecret: rotatedAdvSecret }
	 */
	buildEncryptedPairingRequest(): BinaryNode {
		if(!this.state?.encryptionKey || !this.state.rotatedAdvSecretKey) {
			throw new Error('PasskeyFlow: DH exchange must complete before buildEncryptedPairingRequest()')
		}

		const plaintext = Buffer.from(
			proto.PairingRequest.encode({
				companionPublicKey: this.config.identityKey.public,
				companionIdentityKey: this.config.signedIdentityKey.public,
				advSecret: this.state.rotatedAdvSecretKey,
			}).finish()
		)

		const payload: ShortcakePairingPayload = encryptPairingRequest(this.state.encryptionKey, plaintext)

		const encryptedPairingRequestBytes = Buffer.from(
			proto.EncryptedPairingRequest.encode({
				encryptedPayload: Buffer.concat([payload.encryptedData, payload.tag]),
				iv: payload.iv,
			}).finish()
		)

		return buildEncryptedPairingRequestNode(encryptedPairingRequestBytes)
	}

	/** Returns the rotated ADV secret key for persistence after pairing completes. */
	getRotatedAdvSecretKey(): Buffer {
		if(!this.state?.rotatedAdvSecretKey) {
			throw new Error('PasskeyFlow: state not initialized — call handlePrologueRequest() first')
		}

		return this.state.rotatedAdvSecretKey
	}

	/**
	 * Manual-mode entry point: initialize state from an externally-provided assertion.
	 * Used when no authenticator is configured and the consumer resolves the assertion
	 * themselves after receiving the 'pairing.passkey-request' event.
	 *
	 * pairingRef must be fetched from the server via buildRefQuery() before calling this.
	 */
	async initWithExternalAssertion(
		_notification: BinaryNode,
		assertion: PasskeyAssertion,
		pairingRef: string,
	): Promise<BinaryNode> {
		const deviceType = this.config.deviceType ?? proto.DeviceProps.PlatformType.CHROME
		this.state = initShortcakeState(deviceType, pairingRef, this.config.prevAdvSecretKey)
		return buildPasskeyPrologue({
			credentialId: assertion.credentialId,
			assertionJson: assertion.assertionJson,
			prologuePayloadBytes: this.state.prologuePayloadBytes,
			handoffProof: this.state.handoffProof,
		})
	}

	/** Zero-fill sensitive key material from memory. */
	cleanup(): void {
		if(!this.state) return

		this.state.ephemeralKeyPair.privateKey.fill(0)
		this.state.ephemeralKeyPair.publicKey.fill(0)
		this.state.companionNonce.fill(0)
		this.state.companionEphemeralIdentityBytes.fill(0)
		this.state.prologuePayloadBytes.fill(0)
		this.state.sharedSecret?.fill(0)
		this.state.encryptionKey?.fill(0)
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

		// Standard WebAuthn PublicKeyCredentialRequestOptions field names (confirmed against whatsapp-rust).
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
