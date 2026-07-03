/**
 * passkey-nodes.ts — BinaryNode serialization/deserialization for the Shortcake/PassKey protocol.
 *
 * All tag names and attribute names marked TODO: WIRE_FORMAT are plausible guesses based on
 * whatsapp-rust (jlucaso1) shortcake.rs naming conventions and must be confirmed against the
 * live wire before shipping.
 */

import { getBinaryNodeChild, getBinaryNodeChildBuffer, getBinaryNodeChildString } from '../WABinary/generic-utils'
import type { BinaryNode } from '../WABinary/types'
import type { PasskeyPrologueParams, CrscContinuationData, ShortcakePairingPayload } from '../Types/Passkey'

/**
 * Extract the WebAuthn request options and challenge ID from a passkey_prologue_request
 * notification.
 *
 * TODO: WIRE_FORMAT — confirm child tag name. Observed in whatsapp-rust as
 * `passkey_request_options` (a JSON string child). The `challenge_id` attr location
 * (notification attr vs. inner child) also needs confirmation against shortcake.rs.
 *
 * Expected structure:
 *   <notification type="passkey_prologue_request" id="...">
 *     <passkey_request_options>{JSON}</passkey_request_options>
 *   </notification>
 */
export function parsePasskeyPrologueRequest(node: BinaryNode): {
	requestOptionsJson: string
	challengeId: string
} {
	// TODO: WIRE_FORMAT — tag may be nested under a <passkey> child; confirm depth
	const optionsNode = getBinaryNodeChild(node, 'passkey_request_options')
		?? getBinaryNodeChild(getBinaryNodeChild(node, 'passkey'), 'passkey_request_options')

	if(!optionsNode) {
		throw new Error('passkey_prologue_request: missing <passkey_request_options> child')
	}

	const requestOptionsJson = getBinaryNodeChildString(node, 'passkey_request_options')
		?? (typeof optionsNode.content === 'string' ? optionsNode.content : '')

	if(!requestOptionsJson) {
		throw new Error('passkey_prologue_request: <passkey_request_options> has no text content')
	}

	// TODO: WIRE_FORMAT — challenge_id may be an attribute on the notification or on the inner node
	const challengeId = node.attrs['id'] ?? optionsNode.attrs['challenge_id'] ?? ''

	return { requestOptionsJson, challengeId }
}

/**
 * Build the <passkey_prologue> IQ that sends the WebAuthn assertion and our ephemeral commit
 * to the WhatsApp server.
 *
 * TODO: WIRE_FORMAT — confirm xmlns value ('w:auth:passkey' is a guess; may be 'urn:wa:passkey'
 * or 'md'). Confirm child tag names against whatsapp-rust shortcake.rs build_prologue_iq().
 * The <handoff_proof> child is optional and only sent when re-linking.
 *
 * Expected structure:
 *   <iq type="set" xmlns="w:auth:passkey" id="...">
 *     <passkey_prologue>
 *       <credential_id>{base64}</credential_id>
 *       <webauthn_assertion>{JSON bytes}</webauthn_assertion>
 *       <ephemeral_commit>{raw 32 bytes}</ephemeral_commit>
 *       <handoff_proof>{raw 32 bytes}</handoff_proof>  <!-- omitted if undefined -->
 *     </passkey_prologue>
 *   </iq>
 */
export function buildPasskeyPrologue(params: PasskeyPrologueParams): BinaryNode {
	const { credentialId, assertionJson, ephemeralCommit, handoffProof } = params

	// TODO: WIRE_FORMAT — confirm child order and tag names
	const children: BinaryNode[] = [
		{ tag: 'credential_id', attrs: {}, content: credentialId },
		{ tag: 'webauthn_assertion', attrs: {}, content: assertionJson },
		{ tag: 'ephemeral_commit', attrs: {}, content: ephemeralCommit },
	]

	if(handoffProof) {
		// TODO: WIRE_FORMAT — tag name may be 'handoff_proof' or 'relink_proof'
		children.push({ tag: 'handoff_proof', attrs: {}, content: handoffProof })
	}

	return {
		tag: 'iq',
		attrs: {
			// TODO: WIRE_FORMAT — confirm xmlns
			xmlns: 'w:auth:passkey',
			type: 'set',
		},
		content: [
			{
				tag: 'passkey_prologue',
				attrs: {},
				content: children,
			},
		],
	}
}

/**
 * Extract the server's ephemeral public key and handoff-UX flag from a crsc_continuation
 * notification.
 *
 * TODO: WIRE_FORMAT — confirm child tag names against whatsapp-rust shortcake.rs
 * parse_crsc_continuation(). The <skip_handoff_ux> element may instead be an attribute
 * or have a different tag name ('skip_ux', 'no_handoff', etc.).
 *
 * Expected structure:
 *   <notification type="crsc_continuation" id="...">
 *     <ephemeral>{raw 32 bytes}</ephemeral>
 *     <skip_handoff_ux />   <!-- presence signals true; absence signals false -->
 *   </notification>
 */
export function parseCrscContinuation(node: BinaryNode): CrscContinuationData {
	// TODO: WIRE_FORMAT — tag may be 'server_ephemeral' or 'ephemeral_pub'
	const ephemeralBytes = getBinaryNodeChildBuffer(node, 'ephemeral')
		?? getBinaryNodeChildBuffer(node, 'server_ephemeral')

	if(!ephemeralBytes || ephemeralBytes.length !== 32) {
		throw new Error(
			`crsc_continuation: missing or malformed <ephemeral> child (got ${ephemeralBytes?.length ?? 0} bytes, expected 32)`
		)
	}

	// TODO: WIRE_FORMAT — confirm presence-check semantics (child exists = true)
	const skipHandoffUx = Boolean(getBinaryNodeChild(node, 'skip_handoff_ux'))

	return {
		theirEphemeralPub: Buffer.from(ephemeralBytes),
		skipHandoffUx,
	}
}

/**
 * Build the <encrypted_pairing_request> IQ that delivers the AES-GCM–encrypted identity
 * bundle to the server, along with our revealed ephemeral public key.
 *
 * TODO: WIRE_FORMAT — confirm xmlns and the exact child structure against
 * whatsapp-rust shortcake.rs build_encrypted_pairing_request_iq(). Specifically:
 *   - Whether ephemeral_reveal is the raw 32-byte pub or includes a length prefix
 *   - Whether iv + tag are separate children or concatenated with ciphertext
 *   - Whether there is an outer <passkey> wrapper child
 *
 * Expected structure:
 *   <iq type="set" xmlns="w:auth:passkey" id="...">
 *     <encrypted_pairing_request>
 *       <ephemeral_reveal>{raw 32 bytes}</ephemeral_reveal>
 *       <ciphertext>{encrypted bytes}</ciphertext>
 *       <iv>{12 bytes}</iv>
 *       <tag>{16 bytes}</tag>
 *     </encrypted_pairing_request>
 *   </iq>
 */
export function buildEncryptedPairingRequestNode(
	payload: ShortcakePairingPayload,
	ephemeralPub: Buffer
): BinaryNode {
	const { encryptedData, iv, tag } = payload

	// TODO: WIRE_FORMAT — confirm tag names and whether iv/tag are concatenated
	return {
		tag: 'iq',
		attrs: {
			// TODO: WIRE_FORMAT — confirm xmlns
			xmlns: 'w:auth:passkey',
			type: 'set',
		},
		content: [
			{
				tag: 'encrypted_pairing_request',
				attrs: {},
				content: [
					{ tag: 'ephemeral_reveal', attrs: {}, content: ephemeralPub },
					{ tag: 'ciphertext', attrs: {}, content: encryptedData },
					{ tag: 'iv', attrs: {}, content: iv },
					{ tag: 'tag', attrs: {}, content: tag },
				],
			},
		],
	}
}
