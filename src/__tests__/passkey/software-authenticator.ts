/**
 * In-memory software WebAuthn authenticator for passkey handler E2E tests.
 * Same ES256 logic as whatsapp-gateway passkeyAuthenticator.ts (no Redis).
 */

import {
	createHash,
	createPrivateKey,
	generateKeyPairSync,
	randomBytes,
	sign,
} from 'node:crypto'
import type { PasskeyAssertion, PasskeyAssertionRequest, PasskeyAuthenticator } from '../../Types/Passkey'

export function makeSoftwarePasskeyAuthenticator(
	rpId = 'web.whatsapp.com',
): PasskeyAuthenticator {
	const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' })
	const credentialId = randomBytes(32)
	const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string
	let counter = 0

	return {
		async getAssertion(request: PasskeyAssertionRequest): Promise<PasskeyAssertion> {
			counter++
			const options = JSON.parse(request.rawOptionsJson)
			const clientDataJSON = Buffer.from(
				JSON.stringify({
					type: 'webauthn.get',
					challenge: options.challenge,
					origin: `https://${rpId}`,
					crossOrigin: false,
				}),
			)

			const rpIdHash = createHash('sha256').update(rpId).digest()
			const flags = Buffer.alloc(1, 0x05)
			const counterBuf = Buffer.alloc(4)
			counterBuf.writeUInt32BE(counter)
			const authenticatorData = Buffer.concat([rpIdHash, flags, counterBuf])

			const clientDataHash = createHash('sha256').update(clientDataJSON).digest()
			const signingData = Buffer.concat([authenticatorData, clientDataHash])
			const signature = sign('SHA256', signingData, {
				key: createPrivateKey(privateKeyPem),
				dsaEncoding: 'der',
			})

			return {
				credentialId,
				assertionJson: Buffer.from(
					JSON.stringify({
						authenticatorData: authenticatorData.toString('base64url'),
						clientDataJSON: clientDataJSON.toString('base64url'),
						signature: signature.toString('base64url'),
					}),
				),
			}
		},
	}
}
