/**
 * In-process Shortcake mock server for passkey handler E2E tests.
 * Does not validate WebAuthn — only the Shortcake crypto exchange.
 */

import { randomBytes } from 'node:crypto'
import {
	decryptPairingResponse,
	deriveEncryptionKey,
	deriveSharedSecret,
	generateEphemeralKeyPair,
} from '../../Utils/shortcake'
import { proto } from '../../../WAProto/index.js'
import type { BinaryNode } from '../../WABinary/types'
import { MOCK_PAIRING_REF, MOCK_WEBAUTHN_OPTIONS_JSON } from './mock-webauthn-options'

const DEVICE_TYPE = proto.DeviceProps.PlatformType.CHROME

export function buildCrscContinuation(serverPub: Buffer, serverNonce: Buffer): BinaryNode {
	const primaryEphIdentityBytes = proto.PrimaryEphemeralIdentity.encode({
		publicKey: serverPub,
		nonce: serverNonce,
	}).finish()

	return {
		tag: 'notification',
		attrs: { type: 'crsc_continuation', id: 'crsc-mock-1' },
		content: [{
			tag: 'primary_ephemeral_identity',
			attrs: {},
			content: Buffer.from(primaryEphIdentityBytes),
		}],
	}
}

export function extractCompanionEphPub(prologueIq: BinaryNode): Buffer {
	const prologueChild = (prologueIq.content as BinaryNode[])[0]!
	const children = prologueChild.content as BinaryNode[]
	const payloadNode = children.find(c => c.tag === 'prologue_payload')!
	const payload = proto.ProloguePayload.decode(payloadNode.content as Buffer)
	const ephIdentity = proto.CompanionEphemeralIdentity.decode(
		Buffer.from(payload.companionEphemeralIdentity!)
	)
	return Buffer.from(ephIdentity.publicKey!)
}

export function buildPasskeyPrologueRequestNotification(
	inlineOptions = false,
): BinaryNode {
	if(inlineOptions) {
		return {
			tag: 'notification',
			attrs: { type: 'passkey_prologue_request', id: 'mock-prologue-1' },
			content: [{
				tag: 'passkey_request_options',
				attrs: {},
				content: Buffer.from(MOCK_WEBAUTHN_OPTIONS_JSON),
			}],
		}
	}

	return {
		tag: 'notification',
		attrs: { type: 'passkey_prologue_request', id: 'mock-prologue-1' },
		content: [],
	}
}

const IQ_OK: BinaryNode = { tag: 'iq', attrs: { type: 'result' }, content: [] }

export class ShortcakeMockServer {
	readonly ref: string
	readonly deviceType: number

	private serverKeyPair = generateEphemeralKeyPair()
	private serverNonce = randomBytes(32)
	private companionEphPub: Buffer | null = null
	private lastPairingRequest: proto.IPairingRequest | null = null

	constructor(ref = MOCK_PAIRING_REF, deviceType = DEVICE_TYPE) {
		this.ref = ref
		this.deviceType = deviceType
	}

	getCrscContinuation(): BinaryNode {
		return buildCrscContinuation(this.serverKeyPair.publicKey, this.serverNonce)
	}

	getLastPairingRequest(): proto.IPairingRequest | null {
		return this.lastPairingRequest
	}

	private onPasskeyPrologue(prologueIq: BinaryNode): void {
		this.companionEphPub = extractCompanionEphPub(prologueIq)
		this.serverKeyPair = generateEphemeralKeyPair()
		this.serverNonce = randomBytes(32)
	}

	private onEncryptedPairingRequest(encIq: BinaryNode): void {
		if(!this.companionEphPub) {
			throw new Error('ShortcakeMockServer: no companion ephemeral pub from prologue')
		}

		const encChild = (encIq.content as BinaryNode[])[0]!
		const encReqBytes = Buffer.from(encChild.content as Buffer)
		this.lastPairingRequest = this.decrypt(encReqBytes, this.companionEphPub)
	}

	decrypt(
		encReqBytes: Buffer,
		companionEphPub: Buffer,
	): proto.IPairingRequest {
		const encReq = proto.EncryptedPairingRequest.decode(encReqBytes)
		const sharedSecret = deriveSharedSecret(this.serverKeyPair.privateKey, companionEphPub)
		const encKey = deriveEncryptionKey(sharedSecret, this.deviceType, this.ref)

		const encPayload = Buffer.from(encReq.encryptedPayload!)
		const tag = encPayload.subarray(encPayload.length - 16)
		const ciphertext = encPayload.subarray(0, encPayload.length - 16)
		const iv = Buffer.from(encReq.iv!)

		const plaintext = decryptPairingResponse(encKey, { encryptedData: ciphertext, iv, tag })
		return proto.PairingRequest.decode(plaintext)
	}

	/** Routes companion IQs the way a Meta server would for Shortcake. */
	async routeQuery(node: BinaryNode): Promise<BinaryNode> {
		const firstChild = Array.isArray(node.content) ? node.content[0] as BinaryNode : undefined
		if(!firstChild) return IQ_OK

		if(firstChild.tag === 'ref') {
			return {
				tag: 'iq',
				attrs: { type: 'result' },
				content: [{ tag: 'ref', attrs: {}, content: Buffer.from(this.ref) }],
			}
		}

		if(firstChild.tag === 'passkey_request_options') {
			return {
				tag: 'iq',
				attrs: { type: 'result' },
				content: [{
					tag: 'passkey_request_options',
					attrs: {},
					content: Buffer.from(MOCK_WEBAUTHN_OPTIONS_JSON),
				}],
			}
		}

		if(firstChild.tag === 'passkey_prologue') {
			this.onPasskeyPrologue(node)
			return IQ_OK
		}

		if(firstChild.tag === 'companion_nonce') {
			return IQ_OK
		}

		if(firstChild.tag === 'encrypted_pairing_request') {
			this.onEncryptedPairingRequest(node)
			return IQ_OK
		}

		return IQ_OK
	}
}
