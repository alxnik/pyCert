import binascii, os

from PyCert import X509

def PrintSubject(subj):
    if subj.CommonName() != None:
        print("CN=%s,"%(subj.CommonName())),
    if subj.Organization() != None:
        print("O=%s,"%(subj.Organization())),
    if subj.OrganizationalUnit() != None:
        print("OU=%s,"%(subj.OrganizationalUnit())),
    if subj.StateProvince() != None:
        print("ST=%s,"%(subj.StateProvince())),
    if subj.Country() != None:
        print("C=%s,"%(subj.Country())),
    print("")

CertDir = '/etc/ssl/certs/'
# CertDir='certs/'

failed = []
passed = 0
for File in os.listdir(CertDir):
     
    FullPath = CertDir + File
    if os.path.isdir(FullPath):
        continue
     
    if File.endswith(".0"):
        continue

    
    print(FullPath)
    CertFile = open(FullPath, 'rb')

    try:
        Cert = X509(CertFile.read())
        
        print("             Version: " + str(Cert.Version()))
        
        print("              Serial: " + str(Cert.SerialNumber()))
        
        print("          Not Before: " + str(Cert.ValidNotBefore()))
        print("           Not After: " + str(Cert.ValidNotAfter()))
        print("")
        
        print("              Issuer:"),
        PrintSubject(Cert.Issuer())
        
        print("             Subject:"),
        PrintSubject(Cert.Subject())
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


    except Exception, e:
        fail = {
            "File" : FullPath,
            "Exception" : e
        }
        failed.append(fail)
    else:
        passed += 1
    
    CertFile.close()

print("Passed: %d\nFailed: %d" % (passed, len(failed)))

for fail in failed:
    print("File: [%s], reason: [%s]" %(fail['File'], fail['Exception']))