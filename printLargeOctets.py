import re
import io
import sys
import asn1

import printLargeOctetImport as ploi

#def (self)

certData = io.StringIO()
decoder = asn1.Decoder()

# command to isolate large consumable text for this script
# py irDump.py DoD.ir4 -r | grep -i "2.16.840.1.101.2.1.2.77.3" -A 2 > dodIrDumpGrepout.txt

with open(sys.argv[1], 'rb') as fileIr:
    decoder.start(fileIr.read())
    ploi.pretty_print(decoder, certData, 0)

# print(dir(certData))      
certDataString = certData.getvalue()
certDataLines = certDataString.splitlines()
certData.close()


certCount = 0
certFlag = False
certFlagString = ''
for loc, line in enumerate(certDataLines):
    
    if re.search('\[A\] 0x8', line):
        print(certDataLines[loc+1])


    #if re.search('PRINTABLESTRING|UTF8 STRING|UTCTIME', line):
    #    print(line)

    if re.search('\[C\] 0x0', line) and re.search('\[C\] 0x0', certDataLines[loc+2]):
        if not re.search('BOOLEAN', certDataLines[loc+4]):
            certFlagString += ('ID: {} '.format(certDataLines[loc+4].split(': ',1)[1]))
            certFlag = True

    if certFlag: 
        if re.search('countryName', line):
            certFlagJoiner = certDataLines[loc+1].split(': ', 1)[1]
            certFlagString += 'Country:{}  '.format(certFlagJoiner)
        if re.search('organizationName', line):
            certFlagJoiner = certDataLines[loc+1].split(': ', 1)[1]
            certFlagString += 'ON:{}  '.format(certFlagJoiner)
        if re.search('organizationalUnitName', line):
            certFlagJoiner = certDataLines[loc+1].split(': ', 1)[1]
            certFlagString += 'OU:{}  '.format(certFlagJoiner)
        if re.search('commonName', line):
            certFlagJoiner = certDataLines[loc+1].split(': ', 1)[1]
            certFlagString += 'CN:{}\n'.format(certFlagJoiner)
            certFlag = False


    #print(line)

#print(certCount)
print(certFlagString)
