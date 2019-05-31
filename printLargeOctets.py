import re
import io
import sys
import asn1

import printLargeOctetImport as ploi

certData = io.StringIO()
decoder = asn1.Decoder()

# command to isolate large consumable text for this script
# py irDump.py DoD.ir4 -r | grep -i "2.16.840.1.101.2.1.2.77.3" -A 2 > dodIrDumpGrepout.txt

with open(sys.argv[1], 'rb') as fileIr:
    decoder.start(fileIr.read())
    ploi.pretty_print(decoder, certData, 0)

# print(dir(certData))      
certDataString = certData.getvalue()
certData.close()


buffer = -1
certCount = 0
for line in certDataString.splitlines():
    '''
    if re.search('\[A\] 0x8', line):
        buffer = 1
        print(line)

    if re.search('PRINTABLESTRING|UTF8 STRING|UTCTIME', line):
        print(line)

    if re.search('BIT STRING', line):
        # print(line)
        certCount += 1

    if buffer == 0 and re.search('https', line):
        print('Line count: {} for {}'.format(certCount, line.strip()))
        certCount = 0

    if buffer >= 0:
        buffer -= 1
    '''
    print(line)

#print(certCount)