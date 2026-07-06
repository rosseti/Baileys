import { generateEphemeralKeyPair } from '../../Utils/shortcake'
import type { PasskeyAssertion } from '../../Types/Passkey'
import { MOCK_WEBAUTHN_OPTIONS_JSON } from './mock-webauthn-options'

export const MOCK_CREDS = (() => {
	const identityKey = generateEphemeralKeyPair()
	const signedIdentityKey = generateEphemeralKeyPair()
	return {
		advSecretKey: Buffer.alloc(32, 0x01).toString('base64'),
		noiseKey: { public: identityKey.publicKey, private: identityKey.privateKey },
		signedIdentityKey: {
			public: signedIdentityKey.publicKey,
			private: signedIdentityKey.privateKey,
		},
		identityKey,
		signedIdentityKeyPair: signedIdentityKey,
	}
})()

export const MANUAL_ASSERTION: PasskeyAssertion = {
	credentialId: Buffer.from('manual-test-cred-id'),
	assertionJson: Buffer.from(JSON.stringify({ type: 'webauthn.get' })),
}

export { MOCK_WEBAUTHN_OPTIONS_JSON }
