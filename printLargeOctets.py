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
        self.issuer = ''
        self.subject = ''

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
        print('Failed Future Data')
        return ''

certData = io.StringIO()
decoder = asn1.Decoder()

with open(sys.argv[1], 'rb') as fileIr:
    decoder.start(fileIr.read())
    ploi.pretty_print(decoder, certData, 0)

# print(dir(certData))      
certDataString = certData.getvalue()
certDataLines = certDataString.splitlines()
certData.close()


certCount = 0
certFlag = False
certIssuerFlag = False
certList = []
tempTemplate = None
for loc, line in enumerate(certDataLines):
    lineTag = line.split(': ', 1)[0].strip()
    lineData = line.split(': ', 1)[-1].strip()

    # Line containing TAMP URL, Group, and Store
    if lineTag.startswith('[A] 0x8'):
        print(certDataLines[loc+1])

    # This denotes a standard cert, included in the different groups and stores
    if loc+4 < len(certDataLines) and lineTag == futureTag(certDataLines[loc+2]) == '[C] 0x0':
        if not re.search('BOOLEAN', certDataLines[loc+4]):
            if tempTemplate is not None:
                certList.append(tempTemplate)
            tempTemplate = x509Template(futureData(certDataLines[loc+4]),int(futureData(certDataLines[loc+3])))
            certFlag = True

    # 1.2.840.113549.1.9.16.2.14 is the marking for the timestamped signed cert
    
    try:
        if re.search('rsaEncryption', line):
            do = False
            # print('RSA Encryption: {}\n'.format(certDataLines[loc+2].split(': ', 1)[1][18:-10]))
    except:
        do = True

    if certFlag or certIssuerFlag:
        if re.search('UTCTIME', line):
            tempTemplate.addDate(lineData)
        if re.search('countryName', line):
            certFlagJoiner = 'Country:{},'.format(futureData(certDataLines[loc+1]))
            tempTemplate.addIssuerOrSubject(certFlagJoiner, certIssuerFlag)
        if re.search('organizationName', line):
            certFlagJoiner = 'ON:{}, '.format(futureData(certDataLines[loc+1]))
            tempTemplate.addIssuerOrSubject(certFlagJoiner, certIssuerFlag)
        if re.search('organizationalUnitName', line):
            certFlagJoiner = 'OU:{}, '.format(futureData(certDataLines[loc+1]))
            tempTemplate.addIssuerOrSubject(certFlagJoiner, certIssuerFlag)
        if re.search('commonName', line):
            certFlagJoiner = 'CN:{}'.format(futureData(certDataLines[loc+1]))
            tempTemplate.addIssuerOrSubject(certFlagJoiner, certIssuerFlag)
            if not certIssuerFlag:
                certIssuerFlag = True
            else:
                certFlag = False
                certIssuerFlag = False

    #print(line)

for cert in certList:
    print('\nVersion:{}\nSerial Number: 0x{}'.format(cert.version, cert.certId))
    print('Issuer: {}\nValidity:'.format(cert.issuer))
    print('Not Before: {0[0]}\nNot After: {0[1]}'.format(cert.certDates))
    print('Subject: {}'.format(cert.subject))

