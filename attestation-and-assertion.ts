let attestedCredential;
let importedPubKey;
let jwk;
let assertionCredential;
let challenge;
let userId;
let publicKey: PublicKeyCredentialCreationOptions;
let encoder = new TextEncoder();
let decoder = new TextDecoder();

function concatBuffer(buffer1: ArrayBuffer, buffer2: ArrayBuffer): ArrayBuffer {
    var tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
    tmp.set(new Uint8Array(buffer1), 0);
    tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
    return tmp.buffer;
}

(async function(){
    
    challenge = await crypto.getRandomValues(new Uint8Array(32));
    userId = await crypto.randomUUID();

    publicKey = {
        challenge: encoder.encode(challenge),
        rp: {
            name: "The Server",
            id: location.host,
        },
        user: {
            id: encoder.encode(userId),
            name: "jo@doe.com",
            displayName: "Jo",
        },
        pubKeyCredParams: [{alg: -7, type: "public-key"}],
        authenticatorSelection: {
            authenticatorAttachment: "cross-platform",
        },
        timeout: 60000,
        attestation: "none"
    };
    
    attestedCredential = await navigator.credentials.create({
        publicKey
    });
	importedPubKey = await crypto.subtle.importKey(
        'spki',
        attestedCredential.response.getPublicKey(),
        {name:'ECDSA', namedCurve: 'P-256'},
        true,
        ['verify']
    );
	jwk = await crypto.subtle.exportKey('jwk', importedPubKey);


	assertionCredential = await navigator.credentials.get({
		publicKey: {
			allowCredentials: [{type: 'public-key', id: attestedCredential.rawId, transports: ['nfc', 'usb'] }],
			challenge: encoder.encode(challenge),
			timeout: 60000,
			rpId: publicKey.rp.id,
		}
	});

    const { clientDataJSON, authenticatorData, signature } = assertionCredential.response;

    // Convert from DER ASN.1 encoding to Raw ECDSA signature
    const offset = new Uint8Array(signature)[4] === 0 ? 1 : 0;
    const rawSig = concatBuffer(
        signature.slice(4 + offset, 36 + offset),
        signature.slice(-32),
    );

    const data = concatBuffer(
        authenticatorData,
        await crypto.subtle.digest('SHA-256', clientDataJSON)
    );

    let isVerified = await crypto.subtle.verify(
        {name: "ECDSA", hash: { name: "SHA-256"} },
        importedPubKey,
        rawSig,
        data
    );
    console.log(isVerified);
})();