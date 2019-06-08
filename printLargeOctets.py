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
    
    if re.search('\[A\] 0x8', line):
        print(certDataLines[loc+1])

    if re.search('\[C\] 0x0', line) and re.search('\[C\] 0x0', certDataLines[loc+2]):
        if not re.search('BOOLEAN', certDataLines[loc+4]):
            if tempTemplate is not None:
                certList.append(tempTemplate)
            tempTemplate = x509Template(certDataLines[loc+4].split(': ',1)[1],int(certDataLines[loc+3].split(': ',1)[1]))
            certFlag = True
    
    try:
        if re.search('rsaEncryption', line):
            do = False
            # print('RSA Encryption: {}\n'.format(certDataLines[loc+2].split(': ', 1)[1][18:-10]))
    except:
        do = True

    if certFlag or certIssuerFlag:
        if re.search('UTCTIME', line):
            tempTemplate.addDate(line.split(':', 1)[1])
        if re.search('countryName', line):
            certFlagJoiner = 'Country:{},'.format(certDataLines[loc+1].split(': ', 1)[1])
            tempTemplate.addIssuerOrSubject(certFlagJoiner, certIssuerFlag)
        if re.search('organizationName', line):
            certFlagJoiner = 'ON:{}, '.format(certDataLines[loc+1].split(': ', 1)[1])
            tempTemplate.addIssuerOrSubject(certFlagJoiner, certIssuerFlag)
        if re.search('organizationalUnitName', line):
            certFlagJoiner = 'OU:{}, '.format(certDataLines[loc+1].split(': ', 1)[1])
            tempTemplate.addIssuerOrSubject(certFlagJoiner, certIssuerFlag)
        if re.search('commonName', line):
            certFlagJoiner = 'CN:{}'.format(certDataLines[loc+1].split(': ', 1)[1])
            tempTemplate.addIssuerOrSubject(certFlagJoiner, certIssuerFlag)
            if not certIssuerFlag:
                certIssuerFlag = True
                # certFlagString += '^^^^^^^^^^\nCert Issuer\nCert\n\/\/\/\/\/\/\/\/\n'
            else:
                certFlag = False
                certIssuerFlag = False

    #print(line)
for cert in certList:
    print('\nVersion:{}\nSerial Number: 0x{}'.format(cert.version, cert.certId))
    print('Issuer: {}\nValidity:'.format(cert.issuer))
    print('Not Before: {0[0]}\nNot After: {0[1]}'.format(cert.certDates))
    print('Subject: {}'.format(cert.subject))
