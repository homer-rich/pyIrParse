import re
import io
import sys
import codecs
import asn1
from OpenSSL import crypto
from time import strptime, strftime, gmtime
# ipa houses some functions to print out the asn1 data and other functions
import irParseAsn1 as ipa

certData = io.StringIO()
decoder = asn1.Decoder()

input_data = open(sys.argv[1], 'rb').read()

decoder.start(input_data)
ipa.pretty_print(decoder, certData)

certDataString = certData.getvalue()
certDataLines = certDataString.splitlines()
certData.close()

pertinentAsn1Array = []
for loc, line in enumerate(certDataLines):
    lineData = line.split(': ', 1)[-1].strip()

    # Signing time: 1.2.840.113549.1.9.5
    if '1.2.840.113549.1.9.5' in lineData:
        signingTime = strftime('%B %d %Y %H:%M:%S UTC', strptime(str(ipa.futureData(certDataLines[loc+2])), "%y%m%d%H%M%SZ"))

    if '1.3.6.1.5.5.7.48.1.1' in lineData:
        pertinentAsn1Array.append(ipa.futureData([loc+1]))

    if '2.16.840.1.101.2.1.2.77.3' in lineData and '2.16.840.1.101.3.4.2.1' in ipa.futureData(certDataLines[loc-2]):
        pertinentAsn1Array.append(ipa.futureData(certDataLines[loc+2]))

# 302010202020 indicates an id of the cert
'''findGroup is the Regex that searches for translated URL, Group, and Action that is nestled in 
    the first few hundred bytes of information in the data messages encoded in the TAMP Message

findCertStarts will be used to split the large data message into smaller information, likely 
    to house a cert

findCertEnds is used to find a likely end for the certificate data.  That substring can then 
    be parsed into an X509 cert using Open SSL
'''
findGroup = re.compile(r'(http.*;\w*)\\x02\\x04')
findCertStarts = re.compile(r'(3412.{3,10}|7420.{2,15})A0820')
findCertEnds = re.compile(r'A1820.{4}2820')

print(f'This message was signed on: {signingTime}')
count = 0
for pertinentAsn1 in pertinentAsn1Array:
       
    # Prints the group for each signed section
    if len(pertinentAsn1) > 300:
        group = re.search(findGroup, str(codecs.decode(pertinentAsn1[2:300], 'hex')))
        if group:
            print(group.group(1))

    '''
    Trim off bytes denotation on the front and back of the pertinentAsn1 block and splits
    the larger block into possible certs using the regex
    '''
    possibleCerts = findCertStarts.split(pertinentAsn1[2:-1])
    for miniCertString in possibleCerts:
        try:
            # If there certificate ending regex is found, stop on that byte, else go to end
            searchEnd = re.search(findCertEnds, miniCertString)            
            if searchEnd:
                certBytes = codecs.decode('30820{}'.format(miniCertString[:searchEnd.start()]), 'hex')
            else:
                certBytes = codecs.decode('30820{}'.format(miniCertString), 'hex')
            
            # Load the bytes into a cert, iterate the count and print any information.
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, certBytes)
            count = count + 1
            print('{}, {:X}'.format(cert.get_subject(), cert.get_serial_number()))
            # Pretty Print whole cert
            #print (crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode('utf-8'))
            
        except Exception as e:
            #print(e)
            pass
        
