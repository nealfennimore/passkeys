import { Crypto } from '@peculiar/webcrypto';
import * as x509 from '@peculiar/x509';
import { fromAsn1DERtoRSSignature } from '../../crypto';
import { cborDecode, concatBuffer, decode, toBase64Url } from '../../utils';

describe('Attestation', () => {
    test('attested data for yubikey', async () => {
        const crypto = new Crypto();
        x509.cryptoProvider.set(crypto);

        const challenge = 'XDk8NCPvv70E77-977-9CO-_ve-_vUYQ77-977-9';

        let rawId = new Uint8Array([
            65, 121, 225, 210, 211, 232, 136, 54, 134, 138, 127, 251, 184, 198,
            89, 31, 107, 12, 116, 232, 4, 234, 243, 101, 36, 127, 240, 91, 109,
            252, 39, 117, 149, 226, 12, 12, 84, 232, 191, 95, 129, 102, 213,
            217, 77, 52, 65, 253,
        ]).buffer;
        /** @ts-ignore */
        let response: AuthenticatorAttestationResponse = {
            attestationObject: new Uint8Array([
                163, 99, 102, 109, 116, 102, 112, 97, 99, 107, 101, 100, 103,
                97, 116, 116, 83, 116, 109, 116, 163, 99, 97, 108, 103, 38, 99,
                115, 105, 103, 88, 70, 48, 68, 2, 32, 51, 67, 168, 141, 58, 94,
                254, 197, 17, 83, 155, 243, 230, 66, 90, 103, 252, 225, 214,
                119, 99, 124, 82, 8, 130, 51, 57, 207, 147, 176, 133, 62, 2, 32,
                43, 195, 103, 151, 197, 160, 176, 41, 153, 235, 14, 144, 92, 66,
                213, 116, 235, 138, 97, 131, 230, 216, 101, 65, 198, 186, 1,
                144, 100, 202, 105, 65, 99, 120, 53, 99, 129, 89, 2, 221, 48,
                130, 2, 217, 48, 130, 1, 193, 160, 3, 2, 1, 2, 2, 9, 0, 213, 91,
                156, 104, 151, 162, 202, 136, 48, 13, 6, 9, 42, 134, 72, 134,
                247, 13, 1, 1, 11, 5, 0, 48, 46, 49, 44, 48, 42, 6, 3, 85, 4, 3,
                19, 35, 89, 117, 98, 105, 99, 111, 32, 85, 50, 70, 32, 82, 111,
                111, 116, 32, 67, 65, 32, 83, 101, 114, 105, 97, 108, 32, 52,
                53, 55, 50, 48, 48, 54, 51, 49, 48, 32, 23, 13, 49, 52, 48, 56,
                48, 49, 48, 48, 48, 48, 48, 48, 90, 24, 15, 50, 48, 53, 48, 48,
                57, 48, 52, 48, 48, 48, 48, 48, 48, 90, 48, 111, 49, 11, 48, 9,
                6, 3, 85, 4, 6, 19, 2, 83, 69, 49, 18, 48, 16, 6, 3, 85, 4, 10,
                12, 9, 89, 117, 98, 105, 99, 111, 32, 65, 66, 49, 34, 48, 32, 6,
                3, 85, 4, 11, 12, 25, 65, 117, 116, 104, 101, 110, 116, 105, 99,
                97, 116, 111, 114, 32, 65, 116, 116, 101, 115, 116, 97, 116,
                105, 111, 110, 49, 40, 48, 38, 6, 3, 85, 4, 3, 12, 31, 89, 117,
                98, 105, 99, 111, 32, 85, 50, 70, 32, 69, 69, 32, 83, 101, 114,
                105, 97, 108, 32, 49, 55, 53, 53, 48, 55, 55, 53, 56, 57, 48,
                89, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134, 72,
                206, 61, 3, 1, 7, 3, 66, 0, 4, 1, 6, 169, 208, 127, 234, 89,
                254, 203, 163, 223, 170, 31, 197, 227, 218, 175, 132, 180, 223,
                131, 254, 51, 180, 37, 108, 95, 163, 38, 159, 1, 212, 17, 112,
                129, 200, 133, 67, 34, 198, 171, 106, 7, 215, 221, 228, 207,
                121, 47, 65, 120, 205, 46, 207, 189, 183, 185, 16, 128, 63, 182,
                123, 59, 157, 163, 129, 129, 48, 127, 48, 19, 6, 10, 43, 6, 1,
                4, 1, 130, 196, 10, 13, 1, 4, 5, 4, 3, 5, 4, 3, 48, 34, 6, 9,
                43, 6, 1, 4, 1, 130, 196, 10, 2, 4, 21, 49, 46, 51, 46, 54, 46,
                49, 46, 52, 46, 49, 46, 52, 49, 52, 56, 50, 46, 49, 46, 55, 48,
                19, 6, 11, 43, 6, 1, 4, 1, 130, 229, 28, 2, 1, 1, 4, 4, 3, 2, 5,
                32, 48, 33, 6, 11, 43, 6, 1, 4, 1, 130, 229, 28, 1, 1, 4, 4, 18,
                4, 16, 238, 136, 40, 121, 114, 28, 73, 19, 151, 117, 61, 252,
                206, 151, 7, 42, 48, 12, 6, 3, 85, 29, 19, 1, 1, 255, 4, 2, 48,
                0, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 11, 5, 0, 3,
                130, 1, 1, 0, 132, 52, 202, 250, 234, 23, 200, 213, 10, 191, 51,
                228, 250, 100, 227, 71, 41, 26, 144, 103, 201, 199, 160, 151,
                88, 145, 201, 1, 31, 243, 118, 65, 208, 29, 163, 64, 249, 32,
                124, 207, 118, 182, 150, 105, 253, 176, 18, 136, 219, 255, 189,
                79, 115, 218, 178, 62, 32, 105, 165, 226, 67, 26, 142, 93, 184,
                159, 167, 194, 47, 230, 124, 251, 172, 171, 102, 152, 203, 174,
                175, 251, 184, 249, 115, 36, 58, 143, 176, 45, 214, 111, 114,
                60, 35, 250, 53, 157, 95, 71, 90, 20, 105, 145, 83, 70, 28, 147,
                139, 88, 195, 175, 152, 254, 18, 127, 47, 201, 141, 79, 243,
                157, 187, 104, 234, 99, 127, 190, 90, 86, 124, 79, 209, 254,
                115, 208, 88, 135, 61, 221, 27, 83, 2, 137, 10, 88, 31, 251,
                112, 230, 204, 244, 45, 123, 146, 22, 179, 55, 180, 95, 244,
                200, 71, 161, 130, 220, 3, 192, 3, 91, 203, 211, 134, 236, 170,
                148, 127, 179, 180, 2, 187, 233, 5, 193, 69, 62, 63, 37, 37,
                255, 245, 255, 170, 151, 147, 1, 82, 99, 22, 89, 204, 165, 199,
                192, 219, 46, 152, 71, 105, 7, 184, 172, 249, 126, 140, 226,
                197, 134, 253, 215, 37, 234, 107, 35, 250, 20, 29, 181, 106,
                113, 162, 64, 150, 207, 41, 157, 149, 65, 185, 154, 78, 120,
                214, 251, 115, 170, 147, 35, 51, 165, 47, 68, 72, 53, 193, 104,
                232, 94, 104, 97, 117, 116, 104, 68, 97, 116, 97, 88, 180, 250,
                247, 248, 112, 184, 53, 44, 237, 158, 79, 227, 193, 219, 31,
                225, 187, 249, 254, 83, 239, 87, 77, 45, 67, 242, 189, 97, 31,
                96, 116, 166, 113, 69, 0, 0, 0, 3, 238, 136, 40, 121, 114, 28,
                73, 19, 151, 117, 61, 252, 206, 151, 7, 42, 0, 48, 65, 121, 225,
                210, 211, 232, 136, 54, 134, 138, 127, 251, 184, 198, 89, 31,
                107, 12, 116, 232, 4, 234, 243, 101, 36, 127, 240, 91, 109, 252,
                39, 117, 149, 226, 12, 12, 84, 232, 191, 95, 129, 102, 213, 217,
                77, 52, 65, 253, 165, 1, 2, 3, 38, 32, 1, 33, 88, 32, 65, 121,
                225, 210, 211, 232, 136, 54, 134, 138, 127, 251, 184, 66, 0, 80,
                131, 55, 226, 227, 80, 66, 132, 51, 95, 110, 255, 130, 125, 124,
                101, 222, 34, 88, 32, 173, 201, 104, 175, 80, 113, 52, 138, 138,
                27, 229, 99, 97, 100, 23, 235, 174, 58, 40, 166, 38, 115, 28,
                246, 253, 101, 249, 196, 235, 157, 168, 92,
            ]).buffer,
            clientDataJSON: new Uint8Array([
                123, 34, 99, 104, 97, 108, 108, 101, 110, 103, 101, 34, 58, 34,
                101, 72, 108, 90, 55, 55, 45, 57, 55, 55, 45, 57, 55, 55, 45,
                57, 100, 101, 45, 95, 118, 87, 82, 90, 90, 51, 95, 118, 118, 55,
                49, 74, 55, 55, 45, 57, 69, 81, 34, 44, 34, 111, 114, 105, 103,
                105, 110, 34, 58, 34, 104, 116, 116, 112, 115, 58, 47, 47, 112,
                97, 115, 115, 107, 101, 121, 115, 46, 110, 101, 97, 108, 46, 99,
                111, 100, 101, 115, 34, 44, 34, 116, 121, 112, 101, 34, 58, 34,
                119, 101, 98, 97, 117, 116, 104, 110, 46, 99, 114, 101, 97, 116,
                101, 34, 125,
            ]).buffer,
        };
        /** @ts-ignore */
        let credential: PublicKeyCredential = {
            id: 'QXnh0tPoiDaGin_7uMZZH2sMdOgE6vNlJH_wW238J3WV4gwMVOi_X4Fm1dlNNEH9',
            rawId,
            type: 'public-key',
            response,
        };
        const attestation =
            credential.response as AuthenticatorAttestationResponse;
        const decodedAttestationObject = cborDecode(
            new Uint8Array(attestation.attestationObject)
        );
        expect(decodedAttestationObject).toMatchSnapshot();

        /**
         * Authenticator Data
         * https://www.w3.org/TR/webauthn/#sctn-attestation
         */

        const authData = decodedAttestationObject.authData;
        console.log(authData);

        const rpIdHash = authData.slice(0, 32);
        expect(rpIdHash).toMatchSnapshot('RP ID hash');

        const [flags] = authData.slice(32, 33);
        expect(flags).toMatchSnapshot('Flags');

        // User is present
        expect((flags >>> 0) & 1).toBe(1);

        // User is verified
        expect((flags >>> 2) & 1).toBe(1);

        // Has attested credential data
        expect((flags >>> 6) & 1).toBe(1);

        // Has no extensions
        expect((flags >>> 7) & 1).toBe(0);

        const counter = authData.slice(33, 37);
        expect(counter).toMatchSnapshot('Counter');

        /**
         * https://www.w3.org/TR/webauthn/#sctn-attested-credential-data
         * Attested credential data is a variable-length byte array added to the authenticator data when generating an attestation object for a given credential.
         * NOTE: This does not solve for extensions included!!!
         */
        const attestedCredentialData = authData.slice(37);

        const aaguid = decode(attestedCredentialData.slice(0, 16));
        expect(aaguid).toMatchSnapshot('AAGUID');

        const credentialIdLength: number = new DataView(
            attestedCredentialData.slice(16, 18).buffer
        ).getUint16(0);
        expect(credentialIdLength).toBe(48);

        const credentialId: Uint8Array = attestedCredentialData.slice(
            18,
            18 + credentialIdLength
        );
        expect(credentialId).toMatchSnapshot('Credential ID');

        const credentialPublicKey = cborDecode(
            new Uint8Array(
                attestedCredentialData.slice(18 + credentialIdLength)
            )
        );

        expect(credentialPublicKey).toMatchSnapshot(
            'Credential public key in COSE_Key format'
        );

        /**
         * Attestation Statement
         * https://www.w3.org/TR/webauthn/#sctn-attestation
         */

        const attStmt = decodedAttestationObject.attStmt;

        const clientDataHash = await crypto.subtle.digest(
            'SHA-256',
            credential.response.clientDataJSON
        );
        const signatureBase = concatBuffer(authData, clientDataHash);

        expect(authData).toEqual(
            new Uint8Array(signatureBase.slice(0, authData.length))
        );
        expect(clientDataHash).toEqual(signatureBase.slice(authData.length));

        if (attStmt.hasOwnProperty('x5c')) {
            const cert = new x509.X509Certificate(attStmt.x5c[0]);
            const pubkey = await cert.publicKey.export();

            let rsSig = fromAsn1DERtoRSSignature(attStmt.sig, 256);

            expect(
                await crypto.subtle.verify(
                    { name: 'ECDSA', hash: 'SHA-256' },
                    pubkey,
                    rsSig,
                    signatureBase
                )
            ).toBeTruthy();
        } else {
            // The pubkey of the credential
            const jwk = {
                kty: 'EC',
                crv: 'P-256',
                x: toBase64Url(credentialPublicKey['-2']),
                y: toBase64Url(credentialPublicKey['-3']),
            };
            const pubkey = await crypto.subtle.importKey(
                'jwk',
                jwk,
                { name: 'ECDSA', namedCurve: 'P-256' },
                true,
                ['verify']
            );

            let rsSig = fromAsn1DERtoRSSignature(attStmt.sig, 256);

            expect(
                await crypto.subtle.verify(
                    { name: 'ECDSA', hash: 'SHA-256' },
                    pubkey,
                    rsSig,
                    await crypto.subtle.digest('SHA-256', signatureBase)
                )
            ).toBeTruthy();
            expect(credentialPublicKey[3]).toEqual(attStmt.alg);
        }
    });
});
