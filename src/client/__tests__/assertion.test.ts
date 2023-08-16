import * as x509 from '@peculiar/x509';
import { fromAsn1DERtoRSSignature } from '../../crypto';
import { concatBuffer, decode } from '../../utils';

describe('Assertion', () => {
    test('assertion data for yubikey', async () => {
        const crypto = await import('node:crypto');
        x509.cryptoProvider.set(crypto as Crypto);

        const challenge = 'DzTvv71gFHnvv70ITVDvv71777-9Txpx';

        let rawId = new Uint8Array([
            65, 121, 225, 210, 211, 232, 136, 54, 134, 138, 127, 251, 184, 198,
            89, 31, 107, 12, 116, 232, 4, 234, 243, 101, 36, 127, 240, 91, 109,
            252, 39, 117, 149, 226, 12, 12, 84, 232, 191, 95, 129, 102, 213,
            217, 77, 52, 65, 253,
        ]).buffer;
        /** @ts-ignore */
        let response: AuthenticatorAssertionResponse = {
            authenticatorData: new Uint8Array([
                250, 247, 248, 112, 184, 53, 44, 237, 158, 79, 227, 193, 219,
                31, 225, 187, 249, 254, 83, 239, 87, 77, 45, 67, 242, 189, 97,
                31, 96, 116, 166, 113, 5, 0, 0, 0, 20,
            ]).buffer,
            clientDataJSON: new Uint8Array([
                123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117,
                116, 104, 110, 46, 103, 101, 116, 34, 44, 34, 99, 104, 97, 108,
                108, 101, 110, 103, 101, 34, 58, 34, 68, 122, 84, 118, 118, 55,
                49, 103, 70, 72, 110, 118, 118, 55, 48, 73, 84, 86, 68, 118,
                118, 55, 49, 55, 55, 55, 45, 57, 84, 120, 112, 120, 34, 44, 34,
                111, 114, 105, 103, 105, 110, 34, 58, 34, 104, 116, 116, 112,
                115, 58, 47, 47, 112, 97, 115, 115, 107, 101, 121, 115, 46, 110,
                101, 97, 108, 46, 99, 111, 100, 101, 115, 34, 44, 34, 99, 114,
                111, 115, 115, 79, 114, 105, 103, 105, 110, 34, 58, 102, 97,
                108, 115, 101, 125,
            ]).buffer,
            signature: new Uint8Array([
                48, 70, 2, 33, 0, 131, 54, 225, 204, 91, 50, 254, 48, 161, 75,
                7, 174, 212, 162, 12, 109, 229, 78, 96, 13, 110, 52, 69, 86, 5,
                2, 76, 96, 233, 118, 139, 208, 2, 33, 0, 129, 163, 168, 91, 9,
                9, 180, 194, 92, 24, 193, 205, 122, 240, 141, 105, 108, 169,
                126, 11, 115, 89, 141, 59, 216, 49, 12, 249, 66, 237, 72, 145,
            ]).buffer,
            userHandle: new Uint8Array([
                100, 54, 49, 50, 101, 100, 50, 57, 45, 51, 97, 97, 51, 45, 52,
                98, 98, 55, 45, 56, 50, 98, 99, 45, 49, 54, 55, 55, 57, 48, 56,
                52, 56, 53, 54, 102,
            ]).buffer,
        };
        /** @ts-ignore */
        let credential: PublicKeyCredential = {
            id: 'QXnh0tPoiDaGin_7uMZZH2sMdOgE6vNlJH_wW238J3WV4gwMVOi_X4Fm1dlNNEH9',
            rawId,
            type: 'public-key',
            response,
            authenticatorAttachment: 'platform',
        };
        const assertion = credential.response as AuthenticatorAssertionResponse;
        const { signature } = assertion;

        /**
         * Client Data JSON
         */

        const clientDataJSON = JSON.parse(decode(response.clientDataJSON));

        expect(clientDataJSON).toMatchSnapshot();
        expect(clientDataJSON.challenge).toEqual(challenge);

        /**
         * Authenticator Data
         * https://www.w3.org/TR/webauthn/#sctn-assertion
         */

        const authData = new Uint8Array(assertion.authenticatorData);

        const rpIdHash = authData.slice(0, 32);
        expect(rpIdHash).toMatchSnapshot('RP ID hash');

        const [flags] = authData.slice(32, 33);
        expect(flags).toMatchSnapshot('Flags');

        // User is present
        expect((flags >>> 0) & 1).toBe(1);

        // User is verified
        expect((flags >>> 2) & 1).toBe(1);

        // Has attested credential data
        expect((flags >>> 6) & 1).toBe(0);

        // Has no extensions
        expect((flags >>> 7) & 1).toBe(0);

        const signCount = authData.slice(33, 37);
        expect(signCount).toMatchSnapshot('Sign Counter');
        expect(signCount).toEqual(new Uint8Array([0, 0, 0, 20]));

        /**
         * assertion Statement
         * https://www.w3.org/TR/webauthn/#sctn-assertion
         */

        const clientDataHash = await crypto.subtle.digest(
            'SHA-256',
            credential.response.clientDataJSON
        );
        const signatureBase = concatBuffer(
            assertion.authenticatorData,
            clientDataHash
        );

        expect(authData).toEqual(
            new Uint8Array(signatureBase.slice(0, authData.length))
        );
        expect(clientDataHash).toEqual(signatureBase.slice(authData.length));

        // The pubkey of the credential
        const jwk = {
            kty: 'EC',
            crv: 'P-256',
            x: 'QXnh0tPoiDaGin_7uEIAUIM34uNQQoQzX27_gn18Zd4',
            y: 'rclor1BxNIqKG-VjYWQX6646KKYmcxz2_WX5xOudqFw',
        };

        const pubkey = await crypto.subtle.importKey(
            'jwk',
            jwk,
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
        );

        expect(
            await crypto.subtle.verify(
                { name: 'ECDSA', hash: 'SHA-256' },
                pubkey,
                fromAsn1DERtoRSSignature(signature, 256),
                signatureBase
            )
        ).toBeTruthy();
    });
    test('assertion data for Google passkey', async () => {
        const crypto = await import('node:crypto');
        x509.cryptoProvider.set(crypto as Crypto);

        const challenge = 'De-_vSMNLVjvv71m77-977-9Wu-_vQ3vv71W77-9';

        let rawId = new Uint8Array([
            10, 185, 174, 157, 250, 173, 99, 22, 132, 149, 74, 4, 20, 72, 142,
            242,
        ]).buffer;
        /** @ts-ignore */
        let response: AuthenticatorAssertionResponse = {
            authenticatorData: new Uint8Array([
                250, 247, 248, 112, 184, 53, 44, 237, 158, 79, 227, 193, 219,
                31, 225, 187, 249, 254, 83, 239, 87, 77, 45, 67, 242, 189, 97,
                31, 96, 116, 166, 113, 29, 0, 0, 0, 0,
            ]).buffer,
            clientDataJSON: new Uint8Array([
                123, 34, 116, 121, 112, 101, 34, 58, 34, 119, 101, 98, 97, 117,
                116, 104, 110, 46, 103, 101, 116, 34, 44, 34, 99, 104, 97, 108,
                108, 101, 110, 103, 101, 34, 58, 34, 68, 101, 45, 95, 118, 83,
                77, 78, 76, 86, 106, 118, 118, 55, 49, 109, 55, 55, 45, 57, 55,
                55, 45, 57, 87, 117, 45, 95, 118, 81, 51, 118, 118, 55, 49, 87,
                55, 55, 45, 57, 34, 44, 34, 111, 114, 105, 103, 105, 110, 34,
                58, 34, 104, 116, 116, 112, 115, 58, 92, 47, 92, 47, 112, 97,
                115, 115, 107, 101, 121, 115, 46, 110, 101, 97, 108, 46, 99,
                111, 100, 101, 115, 34, 44, 34, 97, 110, 100, 114, 111, 105,
                100, 80, 97, 99, 107, 97, 103, 101, 78, 97, 109, 101, 34, 58,
                34, 99, 111, 109, 46, 98, 114, 97, 118, 101, 46, 98, 114, 111,
                119, 115, 101, 114, 34, 125,
            ]).buffer,
            signature: new Uint8Array([
                48, 69, 2, 32, 90, 166, 160, 92, 204, 149, 111, 76, 60, 181,
                236, 238, 220, 234, 234, 213, 72, 64, 222, 127, 36, 221, 7, 67,
                182, 235, 191, 170, 204, 87, 41, 198, 2, 33, 0, 133, 19, 208,
                81, 179, 167, 184, 223, 186, 112, 211, 3, 28, 105, 175, 67, 178,
                175, 174, 161, 195, 171, 69, 245, 28, 41, 126, 247, 62, 208,
                240, 180,
            ]).buffer,
            userHandle: new Uint8Array([
                49, 98, 101, 52, 51, 98, 98, 54, 45, 98, 52, 52, 98, 45, 52, 57,
                48, 52, 45, 97, 98, 101, 53, 45, 51, 50, 55, 98, 51, 56, 50, 49,
                100, 52, 55, 49,
            ]).buffer,
        };
        /** @ts-ignore */
        let credential: PublicKeyCredential = {
            id: 'CrmunfqtYxaElUoEFEiO8g',
            rawId,
            type: 'public-key',
            response,
            authenticatorAttachment: 'platform',
        };
        const assertion = credential.response as AuthenticatorAssertionResponse;
        const { signature } = assertion;

        /**
         * Client Data JSON
         */

        const clientDataJSON = JSON.parse(decode(response.clientDataJSON));

        expect(clientDataJSON).toMatchSnapshot();
        expect(clientDataJSON.challenge).toEqual(challenge);

        /**
         * Authenticator Data
         * https://www.w3.org/TR/webauthn/#sctn-assertion
         */

        const authData = new Uint8Array(assertion.authenticatorData);

        const rpIdHash = authData.slice(0, 32);
        expect(rpIdHash).toMatchSnapshot('RP ID hash');

        const [flags] = authData.slice(32, 33);
        expect(flags).toMatchSnapshot('Flags');

        // User is present
        expect((flags >>> 0) & 1).toBe(1);

        // User is verified
        expect((flags >>> 2) & 1).toBe(1);

        // Has attested credential data
        expect((flags >>> 6) & 1).toBe(0);

        // Has no extensions
        expect((flags >>> 7) & 1).toBe(0);

        const signCount = authData.slice(33, 37);
        expect(signCount).toMatchSnapshot('Sign Counter');
        expect(signCount).toEqual(new Uint8Array([0, 0, 0, 0]));

        /**
         * assertion Statement
         * https://www.w3.org/TR/webauthn/#sctn-assertion
         */

        const clientDataHash = await crypto.subtle.digest(
            'SHA-256',
            credential.response.clientDataJSON
        );
        const signatureBase = concatBuffer(
            assertion.authenticatorData,
            clientDataHash
        );

        expect(authData).toEqual(
            new Uint8Array(signatureBase.slice(0, authData.length))
        );
        expect(clientDataHash).toEqual(signatureBase.slice(authData.length));

        // The pubkey of the credential
        const jwk = {
            kty: 'EC',
            crv: 'P-256',
            x: 'qa0xII-mKnptrdb4uMrnYrHeTWNDDYxdyMxpZqzumLs',
            y: '7rWKE_5Rjini2GhN6mnVP7Gys3v648bMd2Sv1d-185g',
        };

        const pubkey = await crypto.subtle.importKey(
            'jwk',
            jwk,
            { name: 'ECDSA', namedCurve: 'P-256' },
            true,
            ['verify']
        );

        expect(
            await crypto.subtle.verify(
                { name: 'ECDSA', hash: 'SHA-256' },
                pubkey,
                fromAsn1DERtoRSSignature(signature, 256),
                signatureBase
            )
        ).toBeTruthy();
    });
});
