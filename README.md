# Passkeys Demo

:warning: **This passkeys demo is not secure.** :warning:

It still needs input validation on everything, however it is at least a somewhat reasonable way of architecting and storing passkeys.

## Architecture

-   Cloudflare workers for server endpoints
-   Cloudflare KV for temporary cache
-   Cloudflare D1 for storing public keys and user information
-   Github pages for the client code

## Passkeys Flows

Any user can have any username they want in this passkeys demo. The client browser generates the user id that will belong to that username, and that user id (which is a uuid v4), is the only piece of information that's stored about the user, along with their public key, and optional attestation data.

Since there's no identifiable user information, this can be considered an anonymous passkey implementation.

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
