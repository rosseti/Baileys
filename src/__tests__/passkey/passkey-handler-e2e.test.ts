/**
 * Handler E2E: real makePasskeyHandlers + real PasskeyFlow + real software authenticator,
 * with ShortcakeMockServer routing IQs (no WebSocket, no Meta).
 */

import { jest } from '@jest/globals'
import { makePasskeyHandlers } from '../../Socket/passkey-handlers'
import { PasskeyFlow } from '../../Socket/passkey-flow'
import type { BinaryNode } from '../../WABinary/types'
import { MOCK_CREDS, MANUAL_ASSERTION } from './passkey-fixtures'
import { makeSoftwarePasskeyAuthenticator } from './software-authenticator'
import {
	ShortcakeMockServer,
	buildPasskeyPrologueRequestNotification,
} from './shortcake-mock-server'

function makeHandlerHarness(opts: {
	authenticator?: ReturnType<typeof makeSoftwarePasskeyAuthenticator>
	prevAdvSecretKey?: Buffer
	inlineOptions?: boolean
}) {
	const mockServer = new ShortcakeMockServer()
	const ev = { emit: jest.fn() } as any
	const query = jest.fn(mockServer.routeQuery.bind(mockServer)) as any
	const sendNode = jest.fn().mockResolvedValue(undefined) as any
	const logger = {
		error: jest.fn(),
		info: jest.fn(),
		debug: jest.fn(),
		warn: jest.fn(),
	} as any

	const authState = {
		creds: {
			...MOCK_CREDS,
			advSecretKey: opts.prevAdvSecretKey
				? opts.prevAdvSecretKey.toString('base64')
				: MOCK_CREDS.advSecretKey,
		},
		keys: {},
	} as any

	const handlers = makePasskeyHandlers({
		ev,
		sendNode,
		query,
		authState,
		passkeyAuthenticator: opts.authenticator,
		logger,
	})

	const notification = buildPasskeyPrologueRequestNotification(opts.inlineOptions ?? false)

	return { handlers, ev, query, mockServer, notification, authState }
}

describe('passkey handler E2E (Shortcake mock server)', () => {
	it('G1 fresh link: auto mode → confirmation code → confirm → decryptable PairingRequest', async () => {
		const { handlers, ev, query, mockServer, notification } = makeHandlerHarness({
			authenticator: makeSoftwarePasskeyAuthenticator(),
		})

		await handlers.handlePrologueRequest(notification)
		await handlers.handleCrscContinuation(mockServer.getCrscContinuation())

		expect(ev.emit).toHaveBeenCalledWith(
			'pairing.passkey-confirmation',
			expect.objectContaining({ skipHandoffUx: false }),
		)

		const confirmCall = (ev.emit as ReturnType<typeof jest.fn>).mock.calls
			.find(([event]) => event === 'pairing.passkey-confirmation')
		const code = confirmCall?.[1]?.code as string
		expect(code).toMatch(/^[0-9A-HJKMNP-TV-Z]{4}-[0-9A-HJKMNP-TV-Z]{4}$/)

		await handlers.confirmPasskeyCode()

		const encCalls = (query as ReturnType<typeof jest.fn>).mock.calls
			.filter(([n]: [BinaryNode]) =>
				Array.isArray(n.content) && (n.content[0] as BinaryNode)?.tag === 'encrypted_pairing_request',
			)
		expect(encCalls).toHaveLength(1)

		const pairingReq = mockServer.getLastPairingRequest()
		expect(pairingReq).not.toBeNull()
		expect(Buffer.from(pairingReq!.companionPublicKey!)).toEqual(MOCK_CREDS.identityKey.publicKey)
		expect(Buffer.from(pairingReq!.companionIdentityKey!)).toEqual(
			MOCK_CREDS.signedIdentityKeyPair.publicKey,
		)
		expect(pairingReq!.advSecret).toHaveLength(32)
	})

	it('G2 re-link: skipHandoffUx true auto-sends encrypted request', async () => {
		const prevAdv = Buffer.alloc(32, 0x99)
		const { handlers, ev, query, mockServer, notification } = makeHandlerHarness({
			authenticator: makeSoftwarePasskeyAuthenticator(),
			prevAdvSecretKey: prevAdv,
		})

		await handlers.handlePrologueRequest(notification)
		await handlers.handleCrscContinuation(mockServer.getCrscContinuation())

		expect(ev.emit).toHaveBeenCalledWith(
			'pairing.passkey-confirmation',
			expect.objectContaining({ skipHandoffUx: true }),
		)

		const encCalls = (query as ReturnType<typeof jest.fn>).mock.calls
			.filter(([n]: [BinaryNode]) =>
				Array.isArray(n.content) && (n.content[0] as BinaryNode)?.tag === 'encrypted_pairing_request',
			)
		expect(encCalls).toHaveLength(1)
		expect(mockServer.getLastPairingRequest()).not.toBeNull()
	})

	it('G3 manual mode: passkey-request → sendPasskeyAssertion → full flow', async () => {
		const { handlers, ev, mockServer, notification } = makeHandlerHarness({})

		const pending = handlers.handlePrologueRequest(notification)
		await Promise.resolve()

		expect(ev.emit).toHaveBeenCalledWith(
			'pairing.passkey-request',
			expect.objectContaining({ deviceId: 'mock-prologue-1' }),
		)

		await handlers.sendPasskeyAssertion(MANUAL_ASSERTION)
		await pending

		await handlers.handleCrscContinuation(mockServer.getCrscContinuation())
		await handlers.confirmPasskeyCode()

		expect(mockServer.getLastPairingRequest()).not.toBeNull()
	})

	it('G4 inline options: skips passkey_request_options IQ fetch', async () => {
		const { handlers, query, mockServer, notification } = makeHandlerHarness({
			authenticator: makeSoftwarePasskeyAuthenticator(),
			inlineOptions: true,
		})

		await handlers.handlePrologueRequest(notification)
		await handlers.handleCrscContinuation(mockServer.getCrscContinuation())

		const optionsFetched = (query as ReturnType<typeof jest.fn>).mock.calls
			.some(([n]: [BinaryNode]) =>
				Array.isArray(n.content) && (n.content[0] as BinaryNode)?.tag === 'passkey_request_options',
			)
		expect(optionsFetched).toBe(false)
	})

	it('G5 cancelPasskeyPairing cleans up without error on idle', async () => {
		const { handlers, ev } = makeHandlerHarness({
			authenticator: makeSoftwarePasskeyAuthenticator(),
		})

		await handlers.handlePrologueRequest(buildPasskeyPrologueRequestNotification())
		handlers.cancelPasskeyPairing()

		expect(ev.emit).toHaveBeenCalledWith(
			'pairing.passkey-error',
			expect.objectContaining({ isContinuable: false }),
		)

		handlers.cancelPasskeyPairing()
		const errorEmits = (ev.emit as ReturnType<typeof jest.fn>).mock.calls
			.filter(([e]) => e === 'pairing.passkey-error')
		expect(errorEmits).toHaveLength(1)
	})

	it('G5b invalid crsc emits passkey-error', async () => {
		const { handlers, ev, notification } = makeHandlerHarness({
			authenticator: makeSoftwarePasskeyAuthenticator(),
		})

		await handlers.handlePrologueRequest(notification)
		await handlers.handleCrscContinuation({
			tag: 'notification',
			attrs: { type: 'crsc_continuation' },
			content: [],
		})

		expect(ev.emit).toHaveBeenCalledWith(
			'pairing.passkey-error',
			expect.objectContaining({ isContinuable: false }),
		)
	})
})

describe('passkey golden path smoke', () => {
	it('runs fresh-link flow end-to-end with real PasskeyFlow class', async () => {
		const mockServer = new ShortcakeMockServer()
		const ev = { emit: jest.fn() } as any
		const handlers = makePasskeyHandlers({
			ev,
			sendNode: jest.fn().mockResolvedValue(undefined) as any,
			query: jest.fn(mockServer.routeQuery.bind(mockServer)) as any,
			authState: { creds: MOCK_CREDS, keys: {} } as any,
			passkeyAuthenticator: makeSoftwarePasskeyAuthenticator(),
			logger: { error: jest.fn(), info: jest.fn(), debug: jest.fn(), warn: jest.fn() } as any,
		}, PasskeyFlow)

		const notification = buildPasskeyPrologueRequestNotification()
		await handlers.handlePrologueRequest(notification)
		await handlers.handleCrscContinuation(mockServer.getCrscContinuation())
		await handlers.confirmPasskeyCode()

		expect(mockServer.getLastPairingRequest()?.advSecret).toHaveLength(32)
	})
})
