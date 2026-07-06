/** Fixture WebAuthn options returned by the mock Meta server. */
export const MOCK_WEBAUTHN_OPTIONS_JSON = JSON.stringify({
	challenge: 'dGVzdC1jaGFsbGVuZ2U',
	rpId: 'web.whatsapp.com',
	allowCredentials: [],
	userVerification: 'required',
	timeout: 600_000,
})

export const MOCK_PAIRING_REF = 'mock-pairing-ref-local'
