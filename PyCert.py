from pyasn1.codec.der import decoder, encoder
from pyasn1.type import univ, namedtype, tag
from pyasn1_modules import rfc2459

import re
from binascii import hexlify


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

def bytes2int(Bytes):
    return int(Bytes.encode('hex'), 16)

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
            InObject = False
            
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

class ECPublicKey():
 
    __ECCurves = {
       "NIST192p" : univ.ObjectIdentifier("1.2.840.10045.3.1.1"),
       "NIST224p" : univ.ObjectIdentifier("1.3.132.0.33"),
       "NIST256p" : univ.ObjectIdentifier("1.2.840.10045.3.1.7"),
       "NIST384p" : univ.ObjectIdentifier("1.3.132.0.34"),
       "NIST521p" : univ.ObjectIdentifier("1.3.132.0.35"),
       "SECP256k1": univ.ObjectIdentifier("1.3.132.0.10")
    }
    
    __CurveMap = None
    
    def __init__(self, payload):
        
        try:
            self.__DecodedParams = decoder.decode(payload.getComponentByName('algorithm').getComponentByName('parameters'), asn1Spec=self.__ParametersAsn())[0]
        except:
            raise ParseError("Invalid ASN1 data")
        
        for curve in self.__ECCurves.keys():
            if self.__DecodedParams == self.__ECCurves[curve]:
                self.__CurveMap = curve
                break
                
        if self.__CurveMap == None:
            raise NotImplementedError("Curve map not supported")
        
        self.__ECPoint = bits2bytes(payload.getComponentByName('subjectPublicKey'))
        
        if self.__ECPoint[0] != '\x04':
            raise NotImplementedError("Compressed EC Key not supported")
        
    def CurveMap(self):
        return self.__CurveMap
    
    def Raw(self):
        return self.__ECPoint[1:]

    class __ParametersAsn(univ.Choice):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('namedCurve', univ.ObjectIdentifier())
            )
        
class RSAPublicKey():
    def __init__(self, payload):
        PKRaw = bits2bytes(payload.getComponentByName('subjectPublicKey'))
        try:
            self.decodedAsn = decoder.decode(PKRaw, asn1Spec=self.__KeyAsn())[0]
        except:
            raise ParseError("Invalid ASN1 data")
        
        self.__params = payload.getComponentByName("algorithm").getComponentByName('parameters')
        self.__payload = payload
        self.__PKRaw = PKRaw
    
    def Modulus(self):
        return self.decodedAsn.getComponentByName('modulus')
    def Exponent(self):
        return self.decodedAsn.getComponentByName('publicExponent')
    
    def Raw(self):
        return self.__PKRaw
    
    def Parameters(self):
        return self.__params
    
    class __KeyAsn(univ.Sequence):
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('modulus', univ.Integer()),
            namedtype.NamedType('publicExponent', univ.Integer())
            )
    

class X509Subject():
    
    def __init__(self, payload = ""):
        self.payload = payload
    
    def __GetValue(self, AttType):
        for RDNSeq in self.payload.getComponentByPosition(0):
            if str(RDNSeq.getComponentByPosition(0).getComponentByName("type")) == AttType:
                return str(RDNSeq.getComponentByPosition(0).getComponentByName("value"))[2:]
            
        return None
                        
    def Country(self):
        return self.__GetValue("2.5.4.6")
    def Organization(self):
        return self.__GetValue("2.5.4.10")
    def OrganizationalUnit(self):
        return self.__GetValue("2.5.4.11")
    def StateProvince(self):
        return self.__GetValue("2.5.4.8")
    def CommonName(self):
        return self.__GetValue("2.5.4.3")
    
    def SerialNumber(self):
        pass
    
    
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
        if Time:
            return datetime.strptime(str(Time), "%y%m%d%H%M%SZ")
        else:
            return None
    
    def ValidNotAfter(self):
        from datetime import datetime
        Time = self.Asn1Obj.getComponentByName('tbsCertificate').getComponentByName('validity').getComponentByName('notAfter').getComponentByName('utcTime')
        if Time:
            return datetime.strptime(str(Time), "%y%m%d%H%M%SZ")
        else:
            return None
        
    def PublicKeyAlgorithm(self):
        Algorithm = self.Asn1Obj.getComponentByName('tbsCertificate').getComponentByName('subjectPublicKeyInfo').getComponentByName('algorithm').getComponentByName('algorithm')
        for algo in PublicKeyAlgorithm.keys():
            if str(Algorithm) == PublicKeyAlgorithm[algo]:
                return algo
            
        raise NotImplementedError
        
    def PublicKey(self):
        payload = self.Asn1Obj.getComponentByName('tbsCertificate').getComponentByName('subjectPublicKeyInfo')
        if self.PublicKeyAlgorithm() == 'rsaEncryption':
            return RSAPublicKey(payload)
        elif self.PublicKeyAlgorithm() == 'id-ecPublicKey':
            return ECPublicKey(payload)
        
    def Subject(self):
        return X509Subject(self.Asn1Obj.getComponentByName('tbsCertificate').getComponentByName('subject'))
    
    def Issuer(self):
        return X509Subject(self.Asn1Obj.getComponentByName('tbsCertificate').getComponentByName('issuer'))
        
    def Signature(self):
        return bits2bytes(self.Asn1Obj.getComponentByName('signatureValue'))
        
    def Verify(self, issuer = None):
        if issuer == None:
            issuer = self
            
        sigAlgo = self.SignatureAlgorithm()
        CertDer = encoder.encode(self.Asn1Obj.getComponentByName('tbsCertificate'))
        
        if sigAlgo == 'sha1WithRSAEncryption' or sigAlgo == 'ecdsa-with-SHA1':
            from Crypto.Hash import SHA
            SigHash = SHA.new(CertDer)
        elif sigAlgo == 'sha256WithRSAEncryption' or sigAlgo == 'ecdsa-with-SHA256':
            from Crypto.Hash import SHA256
            SigHash = SHA256.new(CertDer)
        elif sigAlgo == 'sha384WithRSAEncryption' or sigAlgo == 'ecdsa-with-SHA384':
            from Crypto.Hash import SHA384
            SigHash = SHA384.new(CertDer)
        elif sigAlgo == 'sha512WithRSAEncryption' or sigAlgo == 'ecdsa-with-SHA512':
            from Crypto.Hash import SHA512
            SigHash = SHA512.new(CertDer)
        elif sigAlgo == 'sha224WithRSAEncryption' or sigAlgo == 'ecdsa-with-SHA224':
            from Crypto.Hash import SHA224
            SigHash = SHA224.new(CertDer)
        elif sigAlgo == 'md2WithRSAEncryption':
            from Crypto.Hash import MD2
            SigHash = MD2.new(CertDer)
        elif sigAlgo == 'md4WithRSAEncryption':
            from Crypto.Hash import MD4
            SigHash = MD4.new(CertDer)
        elif sigAlgo == 'md5WithRSAEncryption':
            from Crypto.Hash import MD5
            SigHash = MD5.new(CertDer)
        else:
            raise NotImplementedError('Signature algorithm not supported ({0})'.format(sigAlgo))
        
        
        
        if issuer.PublicKeyAlgorithm() == 'rsaEncryption':
            from Crypto.PublicKey import RSA
            from Crypto.Signature import PKCS1_v1_5
            
            PubKeyDer = issuer.PublicKey().Raw()
            key = RSA.importKey(PubKeyDer)
        
            verifier = PKCS1_v1_5.new(key)
            try:
                if verifier.verify(SigHash, self.Signature()):
                    return True
                else:
                    return False
            except ValueError:
                return False
        
        elif issuer.PublicKeyAlgorithm() == 'id-ecPublicKey':
            from ecdsa import VerifyingKey, NIST192p, NIST224p, NIST256p, NIST384p, NIST521p, SECP256k1
            from ecdsa.util import sigdecode_der
            curves = [NIST192p, NIST224p, NIST256p, NIST384p, NIST521p, SECP256k1]
            
            TheCurve = None
            for crv in curves:
                if crv.name == issuer.PublicKey().CurveMap():
                    TheCurve = crv
                    break
                
            if TheCurve == None:
                raise NotImplementedError('Public Key Curve not supported ({0})'.format(issuer.PublicKey().CurveMap()))
            
            VerKey = VerifyingKey.from_string(issuer.PublicKey().Raw(), curve=TheCurve)
            
            try:
                if VerKey.verify_digest(self.Signature(), SigHash.digest(), sigdecode=sigdecode_der):
                    return True
                else:
                    return False
            except:
                return False
          
        else:
            raise NotImplementedError('Public key algorithm not supported ({0})'.format(issuer.PublicKeyAlgorithm()))

        
        
    def PemDecode(self, CertBuffer):

        Parsed = PemParse(CertBuffer)

        if not Parsed or Parsed == False or Parsed[0]['type'] != 'CERTIFICATE':
            raise ParseError('Invalid PEM Data')
        
        return Parsed[0]['data']
        