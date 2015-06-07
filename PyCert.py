from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, namedtype, tag
from pyasn1_modules import rfc2459

import re, hashlib


class ParseError(Exception):
        def __init__(self, value):
                self.str = value
        def __str__(self):
                return repr(self.str)
            
            
def bits2bytes(bits):
    chars = []
    for b in range(int(len(bits) / 8)):
        byte = bits[b*8:(b+1)*8]
        chars.append(chr(int(''.join([str(bit) for bit in byte]), 2)))
    return ''.join(chars)

def bytes2int(bytes):
    return int(bytes.encode('hex'), 16)

def PemParse(CertBuffer):
    PemStrings = (
            "X509 CERTIFICATE",
            "CERTIFICATE",
            "CERTIFICATE PAIR",
            "TRUSTED CERTIFICATE",
            "NEW CERTIFICATE REQUEST",
            "CERTIFICATE REQUEST",
            "X509 CRL",
            "ANY PRIVATE KEY",
            "PUBLIC KEY",
            "RSA PRIVATE KEY",
            "RSA PUBLIC KEY",
            "DSA PRIVATE KEY",
            "DSA PUBLIC KEY",
            "PKCS7",
            "PKCS #7 SIGNED DATA",
            "ENCRYPTED PRIVATE KEY",
            "PRIVATE KEY",
            "DH PARAMETERS",
            "SSL SESSION PARAMETERS",
            "DSA PARAMETERS",
            "ECDSA PUBLIC KEY",
            "EC PARAMETERS",
            "EC PRIVATE KEY",
            "PARAMETERS",
            "CMS"
            )
    
    if not isinstance(CertBuffer, str):
        try:
            CertBuffer = CertBuffer.decode('utf-8')
        except:
            raise ParseError('Invalid PEM Data')
        
    PemObjects = ()
    
    InObject = False
    for line in CertBuffer.splitlines():
        
        BegMatch = re.match(r'-----BEGIN (.*)-----', line)
        EndMatch = re.match(r'-----END (.*)-----', line)
        
        if(BegMatch):
            if InObject == True:
                raise ParseError('Invalid PEM Data')
            
            ObjectName = BegMatch.group(1)
            
            if ObjectName not in PemStrings:
                raise ParseError('Invalid PEM Data')
            
            InObject = True
            ObjectBuffer = ""
           
            
        elif(EndMatch):
            if InObject == False:
                raise ParseError('Invalid PEM Data')
            
            if EndMatch.group(1) != ObjectName:
                raise ParseError('Invalid PEM Data')
            
            from base64 import b64decode
            parsedObj = {}
            parsedObj['type'] = ObjectName
            parsedObj['data'] = b64decode(ObjectBuffer)
            
            PemObjects += (parsedObj,)
            
        elif InObject == True:
            ObjectBuffer += line
        
        
    return PemObjects
    
PublicKeyAlgorithm = {
    "rsaEncryption"             : "1.2.840.113549.1.1.1",
    "id-ecPublicKey"            : "1.2.840.10045.2.1",
}

SignatureAlgorithm = {
    "md2WithRSAEncryption"      : "1.2.840.113549.1.1.2",
    "md4WithRSAEncryption"      : "1.2.840.113549.1.1.3",
    "md5WithRSAEncryption"      : "1.2.840.113549.1.1.4",
    "sha1WithRSAEncryption"     : "1.2.840.113549.1.1.5",
    "rsaesOaep"                 : "1.2.840.113549.1.1.7",
    "mgf1"                      : "1.2.840.113549.1.1.8",
    "pSpecified"                : "1.2.840.113549.1.1.9",
    "rsassaPss"                 : "1.2.840.113549.1.1.10",
    "sha256WithRSAEncryption"   : "1.2.840.113549.1.1.11",
    "sha384WithRSAEncryption"   : "1.2.840.113549.1.1.12",
    "sha512WithRSAEncryption"   : "1.2.840.113549.1.1.13",
    "sha224WithRSAEncryption"   : "1.2.840.113549.1.1.14",
    
    "ecdsa-with-SHA1"           : "1.2.840.10045.4.1",
    "ecdsa-with-SHA224"         : "1.2.840.10045.4.3.1",
    "ecdsa-with-SHA256"         : "1.2.840.10045.4.3.2",
    "ecdsa-with-SHA384"         : "1.2.840.10045.4.3.3",
    "ecdsa-with-SHA512"         : "1.2.840.10045.4.3.4",
}

RelativeDistinguishedName = {
    "commonName"                : "2.5.4.3",
    "surname"                   : "2.5.4.4",
    "countryName"               : "2.5.4.6",
    "localityName"              : "2.5.4.7",
    "stateOrProvinceName"       : "2.5.4.8",
    "organizationName"          : "2.5.4.10",
    "organizationalUnitName"    : "2.5.4.11"
}

class RSAPublicKey():
    
    def __init__(self, payload):
        
        try:
            self.decodedAsn = decoder.decode(payload, asn1Spec=self.Asn())[0]
        except:
            raise ParseError("Invalid ASN1 data")
        
        self.payload = payload
    
    def Modulus(self):
        return self.decodedAsn.getComponentByName('modulus')
    def Exponent(self):
        return self.decodedAsn.getComponentByName('publicExponent')
    
    def Raw(self):
        return self.payload
    
    class Asn(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('modulus', univ.Integer()),
            namedtype.NamedType('publicExponent', univ.Integer())
            )
    



    
class X509():
    
    def __init__(self, payload = ""):
        
        try:
            payload = self.PemDecode(payload)
        except ParseError:
            pass

        try:
            self.Asn1Obj = decoder.decode(payload, asn1Spec=rfc2459.Certificate())[0]
        except:
            raise ParseError("Invalid ASN1 data")

    def Version(self):
        return self.Asn1Obj.getComponentByName('tbsCertificate').getComponentByName('version') + 1
    
    def SerialNumber(self):
        return self.Asn1Obj.getComponentByName('tbsCertificate').getComponentByName('serialNumber')
    
    def SignatureAlgorithm(self):
        Algorithm = self.Asn1Obj.getComponentByName('tbsCertificate').getComponentByName('signature').getComponentByName('algorithm')
        for algo in SignatureAlgorithm.keys():
            if str(Algorithm) == SignatureAlgorithm[algo]:
                return algo
            
        raise NotImplementedError
        
    def ValidNotBefore(self):
        from datetime import datetime
        Time = self.Asn1Obj.getComponentByName('tbsCertificate').getComponentByName('validity').getComponentByName('notBefore').getComponentByName('utcTime')
        return datetime.strptime(str(Time), "%y%m%d%H%M%SZ")
    
    def ValidNotAfter(self):
        from datetime import datetime
        Time = self.Asn1Obj.getComponentByName('tbsCertificate').getComponentByName('validity').getComponentByName('notAfter').getComponentByName('utcTime')
        return datetime.strptime(str(Time), "%y%m%d%H%M%SZ")
        
    def PublicKeyAlgorithm(self):
        Algorithm = self.Asn1Obj.getComponentByName('tbsCertificate').getComponentByName('subjectPublicKeyInfo').getComponentByName('algorithm').getComponentByName('algorithm')
        for algo in PublicKeyAlgorithm.keys():
            if str(Algorithm) == PublicKeyAlgorithm[algo]:
                return algo
            
        raise NotImplementedError
        
    def PublicKey(self):
        payload = bits2bytes(self.Asn1Obj.getComponentByName('tbsCertificate').getComponentByName('subjectPublicKeyInfo').getComponentByName('subjectPublicKey'))
        if self.PublicKeyAlgorithm() == 'rsaEncryption':
            return RSAPublicKey(payload)
        
    def Signature(self):
        return bits2bytes(self.Asn1Obj.getComponentByName('signatureValue'))
        
    def Verify(self, issuer = None):
        if(issuer == None):
            issuer = self
            
        if(issuer.PublicKeyAlgorithm() == 'rsaEncryption'):
            from Crypto.PublicKey import RSA
            from Crypto.Signature import PKCS1_v1_5
            
            PubKeyDer = issuer.PublicKey().Raw()
            key = RSA.importKey(PubKeyDer)
            
            verifier = PKCS1_v1_5.new(key)
            
            from Crypto.Hash import *
            sigAlgo = self.SignatureAlgorithm()
            CertDer = encoder.encode(self.Asn1Obj.getComponentByName('tbsCertificate'))
            if sigAlgo == 'sha1WithRSAEncryption':
                SigHash = SHA.new(CertDer)
            elif sigAlgo == 'sha256WithRSAEncryption':
                SigHash = SHA256.new(CertDer)
            elif sigAlgo == 'sha384WithRSAEncryption':
                SigHash = SHA384.new(CertDer)
            elif sigAlgo == 'sha512WithRSAEncryption':
                SigHash = SHA512.new(CertDer)
            elif sigAlgo == 'sha224WithRSAEncryption':
                SigHash = SHA224.new(CertDer)
            elif sigAlgo == 'md2WithRSAEncryption':
                SigHash = MD2.new(CertDer)
            elif sigAlgo == 'md4WithRSAEncryption':
                SigHash = MD4.new(CertDer)
            elif sigAlgo == 'md5WithRSAEncryption':
                SigHash = MD5.new(CertDer)
            else:
                raise NotImplementedError
            
            if verifier.verify(SigHash, self.Signature()):
                return True
            else:
                return False
            
        else: # Only RSA implemented
            raise NotImplementedError

        
        
    def PemDecode(self, CertBuffer):

        Parsed = PemParse(CertBuffer)

        if not Parsed or Parsed == False or Parsed[0]['type'] != 'CERTIFICATE':
            raise ParseError('Invalid PEM Data')
        
        return Parsed[0]['data']
        