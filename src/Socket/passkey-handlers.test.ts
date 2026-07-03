/**
 * Unit tests for makePasskeyHandlers.
 *
 * PasskeyFlow is injected via the FlowClass seam (second param) so these tests
 * run without module-level mocks. Coverage: event emission, auto/manual mode
 * branching, companion_nonce IQ, guard clauses, and cleanup semantics.
 */

import { jest } from '@jest/globals'
import { makePasskeyHandlers } from './passkey-handlers'
import type { PasskeyFlowConfig } from './passkey-flow'
import type { BinaryNode } from '../WABinary/types'
import type { PasskeyAssertion, PasskeyAuthenticator } from '../Types/Passkey'

// ── Fixtures ──────────────────────────────────────────────────────────────────

const ROTATED_KEY     = Buffer.alloc(32, 0x42)
const COMPANION_NONCE = Buffer.alloc(32, 0xAA)
// Raw 8-char code returned by the mock flow (no hyphen — handler adds it)
const VERIFICATION_CODE = '12345678'
// Formatted code emitted in pairing.passkey-confirmation
const FORMATTED_CODE    = '1234-5678'

const PROLOGUE_NODE: BinaryNode = { tag: 'passkey_prologue',           attrs: {}, content: [] }
const PAIRING_NODE:  BinaryNode = { tag: 'encrypted_pairing_request',  attrs: {}, content: [] }

const REF_STRING  = 'test-pairing-ref-abc'
const OPTIONS_JSON = '{"challenge":"dGVzdA==","rpId":"whatsapp.com","allowCredentials":[]}'

// Scripted IQ responses returned by the smart query mock (see makeSmartQuery).
const REF_RESULT: BinaryNode = {
	tag: 'iq', attrs: { type: 'result' },
	content: [{ tag: 'ref', attrs: {}, content: Buffer.from(REF_STRING) }],
}
const OPTIONS_RESULT: BinaryNode = {
	tag: 'iq', attrs: { type: 'result' },
	content: [{ tag: 'passkey_request_options', attrs: {}, content: Buffer.from(OPTIONS_JSON) }],
}
const IQ_RESULT: BinaryNode = { tag: 'iq', attrs: { type: 'result' }, content: [] }

const MOCK_ASSERTION: PasskeyAssertion = {
	credentialId:  Buffer.from('cred-id'),
	assertionJson: Buffer.from(JSON.stringify({ type: 'webauthn.get' })),
}

const MOCK_CREDS = {
	advSecretKey:      Buffer.alloc(32, 0x01).toString('base64'),
	noiseKey:          { public: Buffer.alloc(32, 0x02), private: Buffer.alloc(32, 0x03) },
	signedIdentityKey: { public: Buffer.alloc(32, 0x04), private: Buffer.alloc(32, 0x05) },
}

// ── Notification builders ─────────────────────────────────────────────────────

function prologueNotification(): BinaryNode {
	// No inline passkey_request_options → handler must fetch via query
	return { tag: 'notification', attrs: { type: 'passkey_prologue_request', id: 'n1' }, content: [] }
}

function prologueNotificationWithOptions(json: string, challengeId: string): BinaryNode {
	return {
		tag: 'notification',
		attrs: { type: 'passkey_prologue_request', id: challengeId },
		content: [{ tag: 'passkey_request_options', attrs: {}, content: Buffer.from(json) }],
	}
}

function crscNotification(): BinaryNode {
	return { tag: 'notification', attrs: { type: 'crsc_continuation', id: 'n2' }, content: [] }
}

// ── Mock PasskeyFlow ──────────────────────────────────────────────────────────

interface MockFlowInstance {
	handlePrologueRequest:      ReturnType<typeof jest.fn>
	initWithExternalAssertion:  ReturnType<typeof jest.fn>
	handleCrscContinuation:     ReturnType<typeof jest.fn>
	getCompanionNonce:          ReturnType<typeof jest.fn>
	buildEncryptedPairingRequest: ReturnType<typeof jest.fn>
	getRotatedAdvSecretKey:     ReturnType<typeof jest.fn>
	cleanup:                    ReturnType<typeof jest.fn>
}

function makeMockFlow(overrides: Partial<MockFlowInstance> = {}): MockFlowInstance {
	// Cast jest.fn() to `any` before chaining to avoid @jest/globals inferring `never`
	// for the value type parameter of mockResolvedValue / mockReturnValue.
	return {
		handlePrologueRequest:        (jest.fn() as any).mockResolvedValue(PROLOGUE_NODE),
		initWithExternalAssertion:    (jest.fn() as any).mockResolvedValue(PROLOGUE_NODE),
		handleCrscContinuation:       (jest.fn() as any).mockReturnValue({ verificationCode: VERIFICATION_CODE, skipHandoffUx: false }),
		getCompanionNonce:            (jest.fn() as any).mockReturnValue(COMPANION_NONCE),
		buildEncryptedPairingRequest: (jest.fn() as any).mockReturnValue(PAIRING_NODE),
		getRotatedAdvSecretKey:       (jest.fn() as any).mockReturnValue(ROTATED_KEY),
		cleanup:                      jest.fn(),
		...overrides,
	}
}

// ── Smart query mock ──────────────────────────────────────────────────────────
// Returns the correct scripted IQ response based on the first child's tag.

function makeSmartQuery() {
	return (jest.fn() as any).mockImplementation(async (node: unknown) => {
		const n = node as BinaryNode
		const firstChild = Array.isArray(n.content) ? n.content[0] as BinaryNode : undefined
		if(firstChild?.tag === 'ref')                     return REF_RESULT
		if(firstChild?.tag === 'passkey_request_options') return OPTIONS_RESULT
		return IQ_RESULT  // passkey_prologue, companion_nonce, encrypted_pairing_request
	})
}

// ── Factory ───────────────────────────────────────────────────────────────────

function build(
	passkeyAuthenticator?: PasskeyAuthenticator,
	flowOverrides: Partial<MockFlowInstance> = {},
) {
	const mockFlow = makeMockFlow(flowOverrides)
	const MockFlowClass = (jest.fn() as any).mockImplementation((_cfg: any) => mockFlow)

	const ev       = { emit: jest.fn() } as any
	const sendNode = (jest.fn() as any).mockResolvedValue(undefined)  // kept in config, not used
	const query    = makeSmartQuery()
	const authState = { creds: MOCK_CREDS, keys: {} } as any
	const logger   = { error: jest.fn(), info: jest.fn(), debug: jest.fn(), warn: jest.fn() } as any

	const handlers = makePasskeyHandlers(
		{ ev, sendNode, query, authState, passkeyAuthenticator, logger },
		MockFlowClass,
	)

	return { handlers, ev, sendNode, query, logger, mockFlow, MockFlowClass }
}

// ── Auto mode ─────────────────────────────────────────────────────────────────

describe('auto mode (passkeyAuthenticator configured)', () => {
	const authenticator: PasskeyAuthenticator = { getAssertion: jest.fn() as any }

	it('handlePrologueRequest fetches ref, calls PasskeyFlow, and sends prologue via query', async () => {
		const { handlers, query, mockFlow } = build(authenticator)
		const notification = prologueNotification()

		await handlers.handlePrologueRequest(notification)

		// Ref must be fetched from server
		expect(query).toHaveBeenCalledWith(
			expect.objectContaining({ content: expect.arrayContaining([expect.objectContaining({ tag: 'ref' })]) })
		)
		// PasskeyFlow invoked with the fetched ref and options
		expect(mockFlow.handlePrologueRequest).toHaveBeenCalledWith(notification, REF_STRING, OPTIONS_JSON)
		// Prologue node sent via query (not sendNode)
		expect(query).toHaveBeenCalledWith(PROLOGUE_NODE)
	})

	it('handlePrologueRequest skips options fetch when they are inline in the notification', async () => {
		const { handlers, query } = build(authenticator)
		await handlers.handlePrologueRequest(prologueNotificationWithOptions(OPTIONS_JSON, 'cid-1'))

		// Should NOT call query for passkey_request_options
		const optionsFetched = (query as ReturnType<typeof jest.fn>).mock.calls
			.some(([n]: any[]) => Array.isArray(n.content) && n.content[0]?.tag === 'passkey_request_options')
		expect(optionsFetched).toBe(false)
	})

	it('handleCrscContinuation sends companion_nonce IQ then emits pairing.passkey-confirmation', async () => {
		const { handlers, ev, query } = build(authenticator)
		await handlers.handlePrologueRequest(prologueNotification())
		await handlers.handleCrscContinuation(crscNotification())

		// companion_nonce IQ must be sent before the confirmation event
		const nonceCalls = (query as ReturnType<typeof jest.fn>).mock.calls
			.filter(([n]: any[]) => Array.isArray(n.content) && n.content[0]?.tag === 'companion_nonce')
		expect(nonceCalls).toHaveLength(1)

		expect(ev.emit).toHaveBeenCalledWith('pairing.passkey-confirmation', {
			code: FORMATTED_CODE,
			skipHandoffUx: false,
		})
	})

	it('skipHandoffUx=true auto-sends encrypted request without calling confirmPasskeyCode', async () => {
		const { handlers, ev, query } = build(authenticator, {
			handleCrscContinuation: jest.fn().mockReturnValue({ verificationCode: VERIFICATION_CODE, skipHandoffUx: true } as any) as any,
		})

		await handlers.handlePrologueRequest(prologueNotification())
		await handlers.handleCrscContinuation(crscNotification())

		expect(ev.emit).toHaveBeenCalledWith('creds.update', { advSecretKey: ROTATED_KEY.toString('base64') })
		expect(query).toHaveBeenCalledWith(PAIRING_NODE)
	})

	it('skipHandoffUx=false does NOT auto-send — waits for confirmPasskeyCode', async () => {
		const { handlers, query } = build(authenticator)
		await handlers.handlePrologueRequest(prologueNotification())
		await handlers.handleCrscContinuation(crscNotification())

		expect(query).not.toHaveBeenCalledWith(PAIRING_NODE)
	})

	it('confirmPasskeyCode persists rotated key and queries the pairing node', async () => {
		const { handlers, ev, query } = build(authenticator)
		await handlers.handlePrologueRequest(prologueNotification())
		await handlers.handleCrscContinuation(crscNotification())
		await handlers.confirmPasskeyCode()

		expect(ev.emit).toHaveBeenCalledWith('creds.update', { advSecretKey: ROTATED_KEY.toString('base64') })
		expect(query).toHaveBeenCalledWith(PAIRING_NODE)
	})

	it('emits passkey-error and cleans up when handlePrologueRequest throws', async () => {
		const { handlers, ev, mockFlow } = build(authenticator, {
			handlePrologueRequest: (jest.fn() as any).mockRejectedValue(new Error('authenticator refused')),
		})

		await handlers.handlePrologueRequest(prologueNotification())

		expect(ev.emit).toHaveBeenCalledWith('pairing.passkey-error', {
			error: 'authenticator refused',
			isContinuable: false,
		})
		expect(mockFlow.cleanup).toHaveBeenCalled()
	})

	it('emits passkey-error and cleans up when handleCrscContinuation throws', async () => {
		const { handlers, ev, mockFlow } = build(authenticator, {
			handleCrscContinuation: jest.fn().mockImplementation(() => { throw new Error('bad ephemeral') }) as any,
		})

		await handlers.handlePrologueRequest(prologueNotification())
		await handlers.handleCrscContinuation(crscNotification())

		expect(ev.emit).toHaveBeenCalledWith('pairing.passkey-error', {
			error: 'bad ephemeral',
			isContinuable: false,
		})
		expect(mockFlow.cleanup).toHaveBeenCalled()
	})
})

// ── Manual mode ───────────────────────────────────────────────────────────────

describe('manual mode (no passkeyAuthenticator)', () => {
	const CHALLENGE_ID = 'cid-manual-1'

	it('handlePrologueRequest emits pairing.passkey-request with options and deviceId', async () => {
		const { handlers, ev } = build()
		const notification = prologueNotificationWithOptions(OPTIONS_JSON, CHALLENGE_ID)

		const pending = handlers.handlePrologueRequest(notification)
		await Promise.resolve()
		await handlers.sendPasskeyAssertion(MOCK_ASSERTION)
		await pending

		expect(ev.emit).toHaveBeenCalledWith('pairing.passkey-request', {
			requestOptionsJson: OPTIONS_JSON,
			deviceId: CHALLENGE_ID,
		})
	})

	it('sendPasskeyAssertion unblocks the flow, calls initWithExternalAssertion with ref, and sends prologue', async () => {
		const { handlers, query, mockFlow } = build()
		const notification = prologueNotificationWithOptions(OPTIONS_JSON, CHALLENGE_ID)

		const pending = handlers.handlePrologueRequest(notification)
		await Promise.resolve()
		await handlers.sendPasskeyAssertion(MOCK_ASSERTION)
		await pending

		// Must include the server-fetched ref as 3rd argument
		expect(mockFlow.initWithExternalAssertion).toHaveBeenCalledWith(notification, MOCK_ASSERTION, REF_STRING)
		expect(query).toHaveBeenCalledWith(PROLOGUE_NODE)
	})

	it('sendPasskeyAssertion throws if called before handlePrologueRequest', async () => {
		const { handlers } = build()
		await expect(handlers.sendPasskeyAssertion(MOCK_ASSERTION)).rejects.toThrow('No active passkey pairing flow')
	})

	it('sendPasskeyAssertion throws if called after the flow already completed', async () => {
		const { handlers } = build()
		const notification = prologueNotificationWithOptions(OPTIONS_JSON, CHALLENGE_ID)

		const pending = handlers.handlePrologueRequest(notification)
		await Promise.resolve()
		await handlers.sendPasskeyAssertion(MOCK_ASSERTION)
		await pending

		await expect(handlers.sendPasskeyAssertion(MOCK_ASSERTION)).rejects.toThrow('No active passkey pairing flow')
	})
})

// ── Guard clauses ─────────────────────────────────────────────────────────────

describe('confirmPasskeyCode guard', () => {
	it('throws if no flow is active', async () => {
		const { handlers } = build()
		await expect(handlers.confirmPasskeyCode()).rejects.toThrow('No active passkey pairing flow')
	})
})

// ── cancelPasskeyPairing ──────────────────────────────────────────────────────

describe('cancelPasskeyPairing', () => {
	const authenticator: PasskeyAuthenticator = { getAssertion: jest.fn() as any }

	it('emits passkey-error and cleans up while a flow is active', async () => {
		const { handlers, ev, mockFlow } = build(authenticator)
		await handlers.handlePrologueRequest(prologueNotification())

		handlers.cancelPasskeyPairing()

		expect(ev.emit).toHaveBeenCalledWith('pairing.passkey-error', expect.objectContaining({ isContinuable: false }))
		expect(mockFlow.cleanup).toHaveBeenCalled()
	})

	it('is a no-op if no flow is active', () => {
		const { handlers, ev, mockFlow } = build()
		handlers.cancelPasskeyPairing()
		expect(ev.emit).not.toHaveBeenCalled()
		expect(mockFlow.cleanup).not.toHaveBeenCalled()
	})

	it('is idempotent — second cancel does not double-emit', async () => {
		const { handlers, ev } = build(authenticator)
		await handlers.handlePrologueRequest(prologueNotification())

		handlers.cancelPasskeyPairing()
		handlers.cancelPasskeyPairing()

		const errorEmits = (ev.emit as ReturnType<typeof jest.fn>).mock.calls
			.filter(([e]) => e === 'pairing.passkey-error')
		expect(errorEmits).toHaveLength(1)
	})

	it('cancelling in manual mode rejects the pending promise and resolves cleanly', async () => {
		const { handlers } = build()
		const notification = prologueNotificationWithOptions('{"challenge":"x"}', 'cid-x')

		const pending = handlers.handlePrologueRequest(notification)
		await Promise.resolve()
		handlers.cancelPasskeyPairing()

		await expect(pending).resolves.toBeUndefined()
	})
})

// ── onPairSuccess ─────────────────────────────────────────────────────────────

describe('onPairSuccess', () => {
	const authenticator: PasskeyAuthenticator = { getAssertion: jest.fn() as any }

	it('calls cleanup without emitting passkey-error', async () => {
		const { handlers, ev, mockFlow } = build(authenticator)
		await handlers.handlePrologueRequest(prologueNotification())

		handlers.onPairSuccess()

		expect(mockFlow.cleanup).toHaveBeenCalled()
		const errorEmits = (ev.emit as ReturnType<typeof jest.fn>).mock.calls
			.filter(([e]) => e === 'pairing.passkey-error')
		expect(errorEmits).toHaveLength(0)
	})

	it('is idempotent when called with no active flow', () => {
		const { handlers } = build()
		expect(() => handlers.onPairSuccess()).not.toThrow()
	})

	it('after onPairSuccess, confirmPasskeyCode throws because flow is gone', async () => {
		const { handlers } = build(authenticator)
		await handlers.handlePrologueRequest(prologueNotification())
		await handlers.handleCrscContinuation(crscNotification())
		handlers.onPairSuccess()

		await expect(handlers.confirmPasskeyCode()).rejects.toThrow('No active passkey pairing flow')
	})
})
