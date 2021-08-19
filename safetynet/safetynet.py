#
# Safetynet AttestationStatement class and helper functions
#
# Borrowed from:
#	https://gist.github.com/herrjemand/4c7850e53ba4a04cc9e000b41b8e6f8f
#

import base64
import json

import datetime
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from typing import List

gsr2 = b'MIIDdTCCAl2gAwIBAgILBAAAAAABFUtaw5QwDQYJKoZIhvcNAQEFBQAwVzELMAkGA1UEBhMCQkUxGTAXBgNVBAoTEEdsb2JhbFNpZ24gbnYtc2ExEDAOBgNVBAsTB1Jvb3QgQ0ExGzAZBgNVBAMTEkdsb2JhbFNpZ24gUm9vdCBDQTAeFw05ODA5MDExMjAwMDBaFw0yODAxMjgxMjAwMDBaMFcxCzAJBgNVBAYTAkJFMRkwFwYDVQQKExBHbG9iYWxTaWduIG52LXNhMRAwDgYDVQQLEwdSb290IENBMRswGQYDVQQDExJHbG9iYWxTaWduIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDaDuaZjc6j40+Kfvvxi4Mla+pIH/EqsLmVEQS98GPR4mdmzxzdzxtIK+6NiY6arymAZavpxy0Sy6scTHAHoT0KMM0VjU/43dSMUBUc71DuxC73/OlS8pF94G3VNTCOXkNz8kHp1Wrjsok6Vjk4bwY8iGlbKk3Fp1S4bInMm/k8yuX9ifUSPJJ4ltbcdG6TRGHRjcdGsnUOhugZitVtbNV4FpWi6cgKOOvyJBNPc1STE4U6G7weNLWLBYy5d4ux2x8gkasJU26Qzns3dLlwR5EiUWMWea6xrkEmCMgZK9FGqkjWZCrXgzT/LCrBbBlDSgeF59N89iFo7+ryUp9/k5DPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBRge2YaRQ2XyolQL30EzTSo//z9SzANBgkqhkiG9w0BAQUFAAOCAQEA1nPnfE920I2/7LqivjTFKDK1fPxsnCwrvQmeU79rXqoRSLblCKOzyj1hTdNGCbM+w6DjY1Ub8rrvrTnhQ7k4o+YviiY776BQVvnGCv04zcQLcFGUl5gE38NflNUVyRRBnMRddWQVDf9VMOyGj/8N7yy5Y0b2qvzfvGn9LhJIZJrglfCm7ymPAbEVtQwdpf5pLGkkeB6zpxxxYu7KyJesF12KwvhHhm4qxFYxldBniYUr+WymXUadDKqC5JlR3XC321Y9YeRq4VzW9v493kHMB65jUr9TU/Qr6cf9tveCX4XSQRjbgbMEHMUfpIBvFSDJ3gyICh3WZlXi/EjJKSZp4A=='

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
        self._timestampMs = int(payload['timestampMs'])

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
        return self._timestampMs / 1000.0

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
        if (self.timestamp > now):
            raise ValueError('Timestamp exists in the future!')

        return (now - self.timestamp < float(maxAge))

##
## Simple-minded certificate chain validation
##
## We need a better version to be bundled in x509 but alas, it's mired
## in handwringing and bikeshedding.
##
## We need CRL and/or OCSP verification that intermediate certs haven't
## been revoked.
##
def validateCertificatePath(certificates: List[x509.Certificate]) -> bool:
    if len(certificates) != len(set(certificates)):
        return False

    now = datetime.datetime.now()

    for i in range(len(certificates)):
        subjectCert = certificates[i]

        # certificate validity window outside of current time
        if subjectCert.not_valid_before > now or \
           subjectCert.not_valid_after < now:
            return False

        if i == len(certificates) - 1:
            ## root CA's are self-signed, so compare to itself
            issuerCert = certificates[i]
        else:
            issuerCert = certificates[i + 1]

        # check for subject/issuer DN equality
        if subjectCert.issuer != issuerCert.subject:
            return False

        # verify signature using issuer's public key
        try:
            issuerCert.public_key().verify(
                subjectCert.signature,
                subjectCert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                subjectCert.signature_hash_algorithm,
            )
        except InvalidSignature:
            return False

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

def verifySafetyNetAttestation(response: bytes) -> bool:
    attestationBuffer = base64url.decode(response)
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

