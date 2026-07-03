/**
 * passkey-nodes.ts — BinaryNode serialization/deserialization for the Shortcake/PassKey protocol.
 *
 * All tag names, xmlns, and node structures confirmed against:
 * oxidezap/whatsapp-rust src/passkey/flow.rs + wacore/src/shortcake.rs
 */

import { getBinaryNodeChild, getBinaryNodeChildBuffer } from '../WABinary/generic-utils'
import { S_WHATSAPP_NET } from '../WABinary/jid-utils'
import type { BinaryNode } from '../WABinary/types'
import type { PasskeyPrologueParams, CrscContinuationData } from '../Types/Passkey'
import { proto } from '../../WAProto/index.js'

const XMLNS = 'md'

// ─── Notification: passkey_prologue_request ───────────────────────────────────

/**
 * Try to extract the WebAuthn options JSON from a passkey_prologue_request
 * notification. Returns null if absent — caller must fetch via buildRequestOptionsQuery().
 */
export function parsePasskeyPrologueRequest(node: BinaryNode): { requestOptionsJson: string | null } {
	const child = getBinaryNodeChild(node, 'passkey_request_options')
	if(!child) return { requestOptionsJson: null }

	const { content } = child
	if(typeof content === 'string') return { requestOptionsJson: content }
	if(Buffer.isBuffer(content)) return { requestOptionsJson: content.toString('utf8') }
	if(content instanceof Uint8Array) return { requestOptionsJson: Buffer.from(content).toString('utf8') }
	return { requestOptionsJson: null }
}

// ─── GET IQ: <passkey_request_options/> ──────────────────────────────────────

export function buildRequestOptionsQuery(): BinaryNode {
	return {
		tag: 'iq',
		attrs: { xmlns: XMLNS, type: 'get', to: S_WHATSAPP_NET },
		content: [{ tag: 'passkey_request_options', attrs: {}, content: undefined }],
	}
}

export function parseRequestOptionsResponse(node: BinaryNode): string {
	const child = getBinaryNodeChild(node, 'passkey_request_options')
	const { content } = child ?? {}
	if(typeof content === 'string') return content
	if(Buffer.isBuffer(content)) return content.toString('utf8')
	if(content instanceof Uint8Array) return Buffer.from(content).toString('utf8')
	throw new Error('passkey_request_options response: missing or invalid content')
}

// ─── GET IQ: <ref/> — fetch server-issued pairing ref ────────────────────────

export function buildRefQuery(): BinaryNode {
	return {
		tag: 'iq',
		attrs: { xmlns: XMLNS, type: 'get', to: S_WHATSAPP_NET },
		content: [{ tag: 'ref', attrs: {}, content: undefined }],
	}
}

export function parseRefResponse(node: BinaryNode): string {
	const child = getBinaryNodeChild(node, 'ref')
	const { content } = child ?? {}
	if(typeof content === 'string') return content
	if(Buffer.isBuffer(content)) return content.toString('utf8')
	if(content instanceof Uint8Array) return Buffer.from(content).toString('utf8')
	throw new Error('passkey ref response: missing or invalid <ref> content')
}

// ─── SET IQ: <passkey_prologue> ──────────────────────────────────────────────

export function buildPasskeyPrologue(params: PasskeyPrologueParams): BinaryNode {
	const { credentialId, assertionJson, prologuePayloadBytes, handoffProof } = params

	const children: BinaryNode[] = [
		{ tag: 'credential_id', attrs: {}, content: credentialId },
		{ tag: 'webauthn_assertion', attrs: {}, content: assertionJson },
		{ tag: 'prologue_payload', attrs: {}, content: prologuePayloadBytes },
	]

	if(handoffProof) {
		children.push({ tag: 'pairing_handoff_proof', attrs: {}, content: handoffProof })
	}

	return {
		tag: 'iq',
		attrs: { xmlns: XMLNS, type: 'set', to: S_WHATSAPP_NET },
		content: [{ tag: 'passkey_prologue', attrs: {}, content: children }],
	}
}

// ─── Notification: crsc_continuation ─────────────────────────────────────────

/**
 * Extract the server's PrimaryEphemeralIdentity proto from a crsc_continuation
 * notification. skip_handoff_ux is NOT from the server — computed locally in
 * PasskeyFlow from whether a pairing_handoff_proof was sent in the prologue.
 */
export function parseCrscContinuation(node: BinaryNode): CrscContinuationData {
	const rawBytes = getBinaryNodeChildBuffer(node, 'primary_ephemeral_identity')
	if(!rawBytes) {
		throw new Error('crsc_continuation: missing <primary_ephemeral_identity> child')
	}

	const identity = proto.PrimaryEphemeralIdentity.decode(Buffer.from(rawBytes))

	if(identity.publicKey?.length !== 32) {
		throw new Error('crsc_continuation: PrimaryEphemeralIdentity.publicKey missing or wrong length')
	}
	if(identity.nonce?.length !== 32) {
		throw new Error('crsc_continuation: PrimaryEphemeralIdentity.nonce missing or wrong length')
	}

	return {
		primaryPublicKey: Buffer.from(identity.publicKey),
		primaryNonce: Buffer.from(identity.nonce),
	}
}

// ─── SET IQ: <companion_nonce> ────────────────────────────────────────────────

/** Send the companion nonce after crsc_continuation (before encrypting the pairing request). */
export function buildCompanionNonceQuery(companionNonce: Buffer): BinaryNode {
	return {
		tag: 'iq',
		attrs: { xmlns: XMLNS, type: 'set', to: S_WHATSAPP_NET },
		content: [{ tag: 'companion_nonce', attrs: {}, content: companionNonce }],
	}
}

// ─── SET IQ: <encrypted_pairing_request> ─────────────────────────────────────

/**
 * Build the final encrypted pairing request IQ.
 *
 * The serialized EncryptedPairingRequest proto bytes are sent as the direct
 * content of the <encrypted_pairing_request> node (no sub-children). The
 * companion's ephemeral public key is already embedded in the prologue_payload
 * proto sent earlier — no separate ephemeral_reveal node needed.
 */
export function buildEncryptedPairingRequestNode(encryptedPairingRequestBytes: Buffer): BinaryNode {
	return {
		tag: 'iq',
		attrs: { xmlns: XMLNS, type: 'set', to: S_WHATSAPP_NET },
		content: [{
			tag: 'encrypted_pairing_request',
			attrs: {},
			content: encryptedPairingRequestBytes,
		}],
	}
}
