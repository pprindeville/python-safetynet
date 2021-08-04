#
# Safetynet AttestationStatement class and helper functions
#
# Borrowed from:
#	https://gist.github.com/herrjemand/4c7850e53ba4a04cc9e000b41b8e6f8f
#

import base64
import cbor2
import json

import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from typing import List

gsr2 = b'MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4GA1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNpZ24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEGA1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPLv4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklqtTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzdC9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pazq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCBmTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IHV2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5nbG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4GsJ0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavSot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxdAfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg=='

class base64url:
    def encode(s: bytes) -> bytes:
        return base64.b64encode(s, altchars = b'-_').replace(b'=', b'')

    def decode(s: bytes) -> bytes:
        n = len(s) % 4
        if n == 1:
            raise ValueError('Malformed base64 string')
        elif n == 2:
            s += b'=='
        elif n == 3:
            s += b'='
        # nothing to do if already aligned (n == 0)

        return base64.b64decode(s, altchars = b'-_', validate = True)

class AttestationStatement:
    __slots__ = [ \
         '_apkCertificateDigestSha256', '_apkDigestSha256', '_apkPackageName', \
         '_basicIntegrity', '_ctsProfileMatch', '_evaluationType', \
         '_nonce', '_timestampMs', \
    ]

    def __init__(self, payload: dict):
        self._apkCertificateDigestSha256 = \
		[ base64.b64decode(b) for b in payload['apkCertificateDigestSha256'] ]
        self._apkDigestSha256 = base64.b64decode(payload['apkDigestSha256'])
        self._apkPackageName = payload['apkPackageName']
        self._basicIntegrity = payload['basicIntegrity']
        self._ctsProfileMatch = payload['ctsProfileMatch']
        self._evaluationType = (payload['evaluationType'] if 'evaluationType' in payload else None)
        self._nonce = base64.b64decode(payload['nonce'])
        self._timestampMs = payload['timestampMs']

    def __repr__(self) -> str:
        return \
            'AttestationStatement(' \
            f'{self._apkCertificateDigestSha256!r}, {self._apkDigestSha256!r}, {self._apkPackageName!r}, ' \
            f'{self._basicIntegrity!r}, {self._ctsProfileMatch!r}, ' \
            f'{self._evaluationType!r}, ' \
            f'{self._nonce!r}, {self._timestampMs!r}' \
            ')'

    @property
    def apkCertificateDigestSha256(self) -> List[bytes]:
        return self._apkCertificateDigestSha256

    @property
    def apkDigestSha256(self) -> bytes:
        return self._apkDigestSha256

    @property
    def apkPackageName(self) -> bytes:
        return self._apkPackageName

    @property
    def basicIntegrity(self) -> bool:
        return self._basicIntegrity

    @property
    def ctsProfileMatch(self) -> bool:
        return self._ctsProfileMatch

    @property
    def evaluationType(self) -> bytes:
        return self._evaluationType

    @property
    def nonce(self) -> bytes:
        return self._nonce

    @property
    def timestamp(self) -> float:
        return self._timestampMs / 1000

    @property
    def timestampMs(self) -> float:
        return self._timestampMs

    def highIntegrity(self) -> bool:
        return (self._basicIntegrity \
            and self._ctsProfileMatch \
            and (not self._evaluationType is None and self._evaluationType == 'BASIC,HARDWARE_BACKED') \
               )

    def hasValidTs(self, maxAge: int) -> bool:
        now = time.time()
        if (self.timestampMs > now):
            raise ValueError('Timestamp exists in the future!')

        return (now - self.timestamp < float(maxAge))

def validateCertificatePath(certificates: List[x509.Certificate]) -> bool:
    return True

##
## Taken from https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.2
##
def verifySignature_rs256(publicKey: rsa.RSAPublicKey, message: bytes, sig: bytes) -> bool:
    try:
        publicKey.verify(
            sig,
            message,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False

##
## Taken from https://www.rfc-editor.org/rfc/rfc7515.html#appendix-A.1
##
def verifySignature_hs256(key: bytes, message: bytes, sig: bytes) -> bool:
    try:
        h = hmac.HMAC(key, hashes.SHA256())
        h.update(message)
        h.verify(sig)
        return True
    except InvalidSignature:
        return False

def sha256(s: bytes) -> bytes:
    digest = hashes.Hash(hashes.SHA256())
    digest.update(s)
    return digest.finalize()

def verifySafetyNetAttestation(webAuthnResponse: dict) -> bool:
    attestationBuffer = base64url.decode(webAuthnResponse['attestationObject'])
    attestationStruct = cbor2.loads(attestationBuffer)

    if attestationStruct['fmt'] != 'android-safetynet':
        raise ValueError('Attestion using wrong format')

    jwsString = attestationStruct['attStmt']['response']
    jwsParts = jwsString.split(b'.')

    if len(jwsParts) != 3:
        raise RuntimeError('Malformed attestion missing required parts')

    HEADER = json.loads(base64url.decode(jwsParts[0]))
    PAYLOAD = json.loads(base64url.decode(jwsParts[1]))
    SIGNATURE = jwsParts[2]

    ## Verify payload

    clientDataHashBuf = sha256(base64url.decode(webAuthnResponse['clientDataJSON']))

    nonceBase = attestationStruct['authData'] + clientDataHashBuf
    nonceBuffer = sha256(nonceBase)
    expectedNonce = base64.b64encode(nonceBuffer)

    if PAYLOAD['nonce'].encode() != expectedNonce:
        raise RuntimeError('Nonce mismatch in payload')

    ## Verify header

    certs = HEADER['x5c']
    certs.append(gsr2)
    certPath = [ x509.load_der_x509_certificate(base64.b64decode(s)) for s in certs ]

    dn = { attr.oid: attr.value for attr in certPath[0].subject }

    if dn[x509.oid.NameOID.COMMON_NAME] != 'attest.android.com':
        raise RuntimeError('Attestation CN is not "attest.android.com"')

    if not validateCertificatePath(certPath):
        raise RuntimeError('Invalid certificate path')

    if not 'alg' in HEADER:
        raise RuntimeError('No signing algorithm present')

    ## Verify signature

    signatureBaseBuffer = jwsParts[0] + b'.' + jwsParts[1]
    certificate = certPath[0]
    signatureBuffer = base64url.decode(SIGNATURE)

    if HEADER['alg'] == 'RS256':
       signatureIsValid = verifySignature_rs256(certificate.public_key(), signatureBaseBuffer, signatureBuffer)
    ### not entirely clear where the key comes from in this case...
    ##elif HEADER['alg'] == 'HS256':
    ##   signatureIsValid = verifySignature_hs256(certificate.public_key(), signatureBaseBuffer, signatureBuffer)
    else:
       raise Runtime('Unimplemented signing algorithm', HEADER['alg'])

    if not signatureIsValid:
       raise RuntimeError('Invalid signature')

    attestationStmt = AttestationStatement(PAYLOAD)

    # verify the timestamp, nonce, package name, and hashes of the app's
    # signing certificates match expected values in the caller

    return attestationStmt

