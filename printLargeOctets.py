import re
import io
import sys
import asn1

import printLargeOctetImport as ploi

class x509Template:

    def __init__(self, certId, version):
        self.certId = certId
        self.version = version+1
        self.certDates = []
        self.basicConstraints = ()
        self.issuer = ''
        self.subject = ''
        self.publicKey = ''
        self.signatureAlgo = ''
        self.signature = ''

    def addIssuerOrSubject(self, data, isIssuer):
        if isIssuer:
            self.addIssuerData(data)
        else:
            self.addSubjectData(data)

    def addIssuerData(self, data):
        self.issuer += data

    def addSubjectData(self, data):
        self.subject += data

    def addDate(self, date):
        self.certDates.append(date)
    
    def setBasicConstrtaints(self, isCA, secondBool, pathLength):
        self.basicConstraints = (isCA, secondBool, pathLength)

def futureTag(futureLine):
    try:
        return futureLine.split(': ',1)[0].strip()
    except:
        print('Failed Future Tag')
        return ''
def futureData(futureLine):
    try:
        return futureLine.split(': ',1)[1].strip()
    except:
        # print('Failed Future Data')
        return ''

certData = io.StringIO()
decoder = asn1.Decoder()

with open(sys.argv[1], 'rb') as fileIr:
    decoder.start(fileIr.read())
    ploi.pretty_print(decoder, certData, 0)

certDataString = certData.getvalue()
certDataLines = certDataString.splitlines()
certData.close()


certCount = 0
certFlag = False
certIssuerFlag = True
certList = []
tempTemplate = None
for loc, line in enumerate(certDataLines):
    lineTag = line.split(': ', 1)[0].strip()
    lineData = line.split(': ', 1)[-1].strip()

    # Line containing TAMP URL, Group, and Store
    if lineTag.startswith('[A] 0x8'):
        if futureTag(certDataLines[loc+1]).startswith('[C]'):
            print(certDataLines[loc+1])

    # This denotes a standard cert, included in the different groups and stores
    if loc+6 < len(certDataLines) and lineTag == futureTag(certDataLines[loc+2]) == '[C] 0x0':
        if not re.search('BOOLEAN', certDataLines[loc+4]):
            if tempTemplate is not None:
                certList.append(tempTemplate)
                #print('\nVersion:{}\nSerial Number: 0x{}'.format(tempTemplate.version, tempTemplate.certId))
                #print('Issuer: {}\nValidity:'.format(tempTemplate.issuer))
                #print('Public Key: {}'.format(tempTemplate.publicKey))
                #print('Not Before: {0[0]}\nNot After: {0[1]}'.format(tempTemplate.certDates))
                #print('Subject: {}'.format(tempTemplate.subject))

            tempTemplate = x509Template(futureData(certDataLines[loc+4]),int(futureData(certDataLines[loc+3])))
            tempTemplate.signatureAlgo = futureData(certDataLines[loc+6])
            certFlag = True
            certIssuerFlag = True

    # 1.2.840.113549.1.9.16.2.14 is the marking for the timestamped signed cert
    
    if certFlag:
        if re.search('UTCTIME', line):
            tempTemplate.addDate(lineData)
        if re.search('countryName', line):
            certFlagJoiner = 'Country:{},'.format(futureData(certDataLines[loc+1]))
            tempTemplate.addIssuerOrSubject(certFlagJoiner, certIssuerFlag)
        if re.search('organizationName', line):
            certFlagJoiner = 'ON:{},'.format(futureData(certDataLines[loc+1]))
            tempTemplate.addIssuerOrSubject(certFlagJoiner, certIssuerFlag)
        if re.search('organizationalUnitName', line):
            certFlagJoiner = 'OU:{},'.format(futureData(certDataLines[loc+1]))
            tempTemplate.addIssuerOrSubject(certFlagJoiner, certIssuerFlag)
        if re.search('commonName', line):
            certFlagJoiner = 'CN:{}'.format(futureData(certDataLines[loc+1]))
            tempTemplate.addIssuerOrSubject(certFlagJoiner, certIssuerFlag)
            if certIssuerFlag:
                certIssuerFlag = False

        if re.search('X509v3 Basic Constraints', line):
            #if 'BOOLEAN' in futureTag(certDataLines[loc+3]):
            #print(futureData(certDataLines[loc+2]))
            print(futureData(certDataLines[loc+3]))

            tempTemplate.setBasicConstrtaints(
                futureData(certDataLines[loc+1]) if 'BOOLEAN' in futureTag(certDataLines[loc+1]) else None, True, 0
            )
            #print(futureTag(certDataLines[loc+3]))
            #print(futureTag(certDataLines[loc+4]))
            print('EndCert')

        try:
            if re.search('OBJECT: rsaEncryption', line) or re.search('OBJECT: EC', line) and certFlag:
                tempTemplate.publicKey = 'Public Key: {}\n'.format(certDataLines[loc+2].split(': ', 1)[1][18:-10])
        except:
            continue

    if (tempTemplate is not None and certFlag and lineData == tempTemplate.signatureAlgo 
    and loc + 2 < len(certDataLines)):
        if re.search('BIT STRING', futureTag(certDataLines[loc+1])):
            tempTemplate.signature = futureData(certDataLines[loc+1])[2:]
        elif re.search('BIT STRING', futureTag(certDataLines[loc+2])):
            tempTemplate.signature = futureData(certDataLines[loc+2])[2:]
        else:
            continue
        
        certFlag = False
        


#for cert in certList:
    #if cert.publicKey == '':
        #print('\nVersion:{}\nSerial Number: 0x{}'.format(cert.version, cert.certId))
        #print('Issuer: {}\nValidity:'.format(cert.issuer))
        #print('Not Before: {0[0]}\nNot After: {0[1]}'.format(cert.certDates))
        #print('{}'.format(cert.publicKey))
        #print('Subject: {}'.format(cert.subject))
        #print('Algo: {} and the data:\n {}'.format(cert.signatureAlgo, cert.signature))

