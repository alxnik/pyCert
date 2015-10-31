import binascii, os

from PyCert import X509, PemParse

def PrintCert(CertData):
    try:
        Cert = X509(thedata)
        
        print("             Version: " + str(Cert.Version()))
         
        print("              Serial: " + str(Cert.SerialNumber()))
         
        print("          Not Before: " + str(Cert.ValidNotBefore()))
        print("           Not After: " + str(Cert.ValidNotAfter()))
        print("")

        print("              Issuer: %s" % (Cert.Issuer() ))
         
        print("             Subject: %s" % (Cert.Subject() ))
        print("")
         
        print("Public Key Algorithm: " + Cert.PublicKeyAlgorithm())
         
        if Cert.PublicKeyAlgorithm() == 'rsaEncryption':
            print("  Public Key Modulus: %x" % Cert.PublicKey().Modulus())
            print(" Public Key Exponent: " + str(Cert.PublicKey().Exponent()))
         
        print("")
        print(" Signature Algorithm: " + Cert.SignatureAlgorithm())
        print("           Signature: " + binascii.hexlify(Cert.Signature()))
        print("           Verified?: " + str(Cert.Verify()))
     
        print(" -------- ")


    except Exception as e:
#         raise
        return False, e
    else:
        return True, None
    
    
    
CertDir = '/etc/ssl/certs/'
# CertDir='certs/'

failed = []
passed = 0

for File in os.listdir(CertDir):
     
    FullPath = CertDir + File
    if os.path.isdir(FullPath):
        continue
    
    CertFile = open(FullPath, 'rb')
    
    thedata = CertFile.read()
    try:
        certs = PemParse(thedata)
    except Exception as e:
        failed.append({ "File" : FullPath, "Exception" : str(e) })
        continue
    
    for cert in certs:
        rv, e = PrintCert(cert)
    
        if rv == True:
            passed += 1
        else:
            failed.append({ "File" : FullPath, "Exception" : str(e) })


    CertFile.close()
#     break

print("Passed: %d\nFailed: %d" % (passed, len(failed)))

for fail in failed:
    print("File: [%s], reason: [%s]" %(fail['File'], fail['Exception']))