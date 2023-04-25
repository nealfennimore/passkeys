# Passkeys Demo

:warning: **This passkeys demo is not secure.** :warning:

It still needs input validation on everything, however it is at least a somewhat reasonable way of architecting and storing passkeys.

## Architecture

-   Cloudflare workers for server endpoints
-   Cloudflare KV for temporary cache
-   Cloudflare D1 for storing public keys and user information
-   Github pages for the client code

### Database

See [database schema](https://github.com/nealfennimore/passkeys/blob/main/src/server/db/schema/schema.sql).

```mermaid
erDiagram
	users {
        text id PK "Stored as UUID"
		timestamp created_at
    }
    public_keys {
        text kid PK "Stored as UUID"
        blob pubkey
        blob attestation_data
		int cose_alg
		blob sign_counter
		text user_id FK "Stored as UUID"
		timestamp created_at
		timestamp updated_at
    }

	users ||--|{ public_keys: contains
```

### Cache

All challenges expire in 5 minutes. All sessions expire in 24 hours.

```mermaid
erDiagram
	challenges {
        string session_type "Key of 'session_uuid:webauthn_type'"
		string challenge "Random challenge generated for session"
    }

	sessions {
		string session_id "Session UUID"
		string user_id "UUID of user"
	}
```

## Passkeys Flows

Any user can have any username they want in this passkeys demo. The client browser generates the user id that will belong to that username, and that user id (which is an uuid v4) is the only piece of information that's stored about the user, along with their public key, and optional attestation data.

Since there's no identifiable user information, this can be considered an anonymous passkey implementation. As such, you'd be missing a way of keeping in touch with your users were you to implement the same demo.

### Attestation

```mermaid
sequenceDiagram
	participant A as Authenticator
	participant C as Client
	participant S as Server


	note over C, S: API /attestation/generate
	C ->> S: Get a challenge
	S -->> C: Receive challenge

	C ->> A: Generate a key pair
	note right of A: Authenticator stores private key
	A -->> C: Return public key

	note over C, S: API /attestation/store
	C ->> S: Send pubkey and challenge
	note left of S: Store pubkey
	S -->> C: Success
```

### Assertion

```mermaid
sequenceDiagram
	participant A as Authenticator
	participant C as Client
	participant S as Server

	note over C, S: API /assertion/generate
	C ->> S: Get a challenge
	S -->> C: Receive challenge

	C ->> A: Send challenge to use for signing
	A -->> C: Return signature

	note over C, S: API /assertion/verify
	C ->> S: Send signature
	note left of S: Server verifies signature
	S -->> C: Successfully verified
```
