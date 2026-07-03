import type { BinaryNode } from '../WABinary/types'
import type { BaileysEventEmitter } from '../Types/Events'
import type { AuthenticationState } from '../Types/Auth'
import type { PasskeyAuthenticator, PasskeyAssertion } from '../Types/Passkey'
import type { ILogger } from '../Utils/logger'
import { PasskeyFlow } from './passkey-flow'
import {
	parsePasskeyPrologueRequest,
	buildRequestOptionsQuery,
	parseRequestOptionsResponse,
	buildRefQuery,
	parseRefResponse,
	buildCompanionNonceQuery,
} from './passkey-nodes'

export interface PasskeyHandlerConfig {
	ev: BaileysEventEmitter
	sendNode: (node: BinaryNode) => Promise<void>
	query: (node: BinaryNode) => Promise<BinaryNode>
	authState: AuthenticationState
	passkeyAuthenticator?: PasskeyAuthenticator
	logger: ILogger
}

export function makePasskeyHandlers(
	config: PasskeyHandlerConfig,
	/** Seam for testing — defaults to the real PasskeyFlow in production. */
	FlowClass: typeof PasskeyFlow = PasskeyFlow
) {
	const { ev, query, authState, passkeyAuthenticator, logger } = config

	const flow = new FlowClass({
		authenticator: passkeyAuthenticator,
		prevAdvSecretKey: authState.creds.advSecretKey
			? Buffer.from(authState.creds.advSecretKey, 'base64')
			: undefined,
		identityKey: {
			public: Buffer.from(authState.creds.noiseKey.public),
			private: Buffer.from(authState.creds.noiseKey.private),
		},
		signedIdentityKey: {
			public: Buffer.from(authState.creds.signedIdentityKey.public),
			private: Buffer.from(authState.creds.signedIdentityKey.private),
		},
	})

	let flowActive = false
	let pendingAssertionResolve: ((assertion: PasskeyAssertion) => void) | null = null
	let pendingAssertionReject: ((err: Error) => void) | null = null

	const _cleanup = (): void => {
		if(pendingAssertionReject) {
			pendingAssertionReject(new Error('Passkey pairing cancelled'))
			pendingAssertionResolve = null
			pendingAssertionReject = null
		}

		flowActive = false
		flow.cleanup()
	}

	const _doSendEncryptedPairingRequest = async (): Promise<void> => {
		// Persist the rotated ADV key BEFORE the query so that when pair-success
		// arrives and configureSuccessfulPairing() verifies the HMAC, it uses
		// the rotated key already stored in creds.
		const rotatedKey = flow.getRotatedAdvSecretKey()
		ev.emit('creds.update', { advSecretKey: rotatedKey.toString('base64') })

		const pairingNode = flow.buildEncryptedPairingRequest()
		await query(pairingNode)
		// pair-success arrives as a separate stanza handled by socket.ts CB:iq,,pair-success,
		// which calls onPairSuccess() below for cleanup.
	}

	const handlePrologueRequest = async (notification: BinaryNode): Promise<void> => {
		flowActive = true
		try {
			// 1. Get options JSON — inline in the notification, or fetch via IQ
			let optionsJson: string | null = parsePasskeyPrologueRequest(notification).requestOptionsJson
			if(!optionsJson) {
				const resp = await query(buildRequestOptionsQuery())
				optionsJson = parseRequestOptionsResponse(resp)
			}

			// 2. Fetch the server-issued pairing ref (baked into the HKDF salt)
			const refResp = await query(buildRefQuery())
			const pairingRef = parseRefResponse(refResp)

			if(passkeyAuthenticator) {
				// Auto mode: PasskeyFlow resolves the WebAuthn assertion internally
				const prologueNode = await flow.handlePrologueRequest(notification, pairingRef, optionsJson)
				await query(prologueNode)
			} else {
				// Manual mode: emit event, wait for the app to supply an assertion
				ev.emit('pairing.passkey-request', {
					requestOptionsJson: optionsJson,
					deviceId: notification.attrs['id'] ?? '',
				})

				const assertion = await new Promise<PasskeyAssertion>((resolve, reject) => {
					pendingAssertionResolve = resolve
					pendingAssertionReject = reject
				})

				const prologueNode = await flow.initWithExternalAssertion(notification, assertion, pairingRef)
				await query(prologueNode)
			}
		} catch(error: any) {
			logger.error({ error }, 'passkey: prologue request failed')
			_cleanup()
			ev.emit('pairing.passkey-error', { error: error?.message ?? String(error), isContinuable: false })
		}
	}

	const handleCrscContinuation = async (notification: BinaryNode): Promise<void> => {
		try {
			const { verificationCode, skipHandoffUx } = flow.handleCrscContinuation(notification)

			// Send companion nonce before sending the encrypted pairing request
			// (confirmed from whatsapp-rust: companion_nonce IQ is sent after crsc_continuation)
			await query(buildCompanionNonceQuery(flow.getCompanionNonce()))

			// Format as "XXXX-XXXX" for display (confirmed from whatsapp-rust CODE_GROUP_LEN=4)
			const code = `${verificationCode.slice(0, 4)}-${verificationCode.slice(4)}`

			ev.emit('pairing.passkey-confirmation', { code, skipHandoffUx })

			if(skipHandoffUx) {
				await _doSendEncryptedPairingRequest()
			}
		} catch(error: any) {
			logger.error({ error }, 'passkey: crsc continuation failed')
			_cleanup()
			ev.emit('pairing.passkey-error', { error: error?.message ?? String(error), isContinuable: false })
		}
	}

	const sendPasskeyAssertion = async (assertion: PasskeyAssertion): Promise<void> => {
		if(!pendingAssertionResolve) {
			throw new Error('No active passkey pairing flow')
		}

		pendingAssertionResolve(assertion)
		pendingAssertionResolve = null
		pendingAssertionReject = null
	}

	const confirmPasskeyCode = async (): Promise<void> => {
		if(!flowActive) {
			throw new Error('No active passkey pairing flow')
		}

		try {
			await _doSendEncryptedPairingRequest()
		} catch(error: any) {
			logger.error({ error }, 'passkey: confirm code failed')
			_cleanup()
			ev.emit('pairing.passkey-error', { error: error?.message ?? String(error), isContinuable: false })
			throw error
		}
	}

	/** Public cancel: cleans up and emits 'pairing.passkey-error'. No-op if no flow is active. */
	const cancelPasskeyPairing = (): void => {
		if(!flowActive) return

		_cleanup()
		ev.emit('pairing.passkey-error', { error: 'Pairing cancelled by user', isContinuable: false })
	}

	/** Internal: clean up after pair-success without emitting an error event. */
	const onPairSuccess = (): void => {
		_cleanup()
	}

	return {
		handlePrologueRequest,
		handleCrscContinuation,
		sendPasskeyAssertion,
		confirmPasskeyCode,
		cancelPasskeyPairing,
		onPairSuccess,
	}
}
