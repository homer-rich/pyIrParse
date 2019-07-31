import re
import io
import sys
import codecs
import asn1
import ssl
import pdb
from OpenSSL import crypto
from time import strptime, strftime, gmtime, mktime
# ipa houses some functions to print out the asn1 data and prune said data
import IrParseAsn1 as ipa
# rws houses the ability to access windows cert stores for comparison to the ir4 file
import os
isWindows = os.name == 'nt'
if isWindows:
    import ReadWindowsStores as rws

certData = io.StringIO()
decoder = asn1.Decoder()

input_data = open(sys.argv[1], 'rb').read()

decoder.start(input_data)
ipa.pretty_print(decoder, certData)

certDataString = certData.getvalue()
certDataLines = certDataString.splitlines()
certData.close()

pertinentAsn1Array = []
signingTime = None
for loc, line in enumerate(certDataLines):
    lineData = line.split(': ', 1)[-1].strip()

    # Signing time: 1.2.840.113549.1.9.5
    if '1.2.840.113549.1.9.5' in lineData and not signingTime:
        time = strptime(str(ipa.futureData(certDataLines[loc+2])), '%y%m%d%H%M%SZ')
        signingTime = strftime('%B %d %Y %H:%M:%S UTC',  
                strptime(str(ipa.futureData(certDataLines[loc+2])), '%y%m%d%H%M%SZ'))
        print('Epoch Time for .reg files: {}'.format(int(mktime(time))))

    if '1.3.6.1.5.5.7.48.1.1' in lineData:
        pertinentAsn1Array.append(ipa.futureData([loc+1]))

    if '2.16.840.1.101.2.1.2.77.3' in lineData and \
        '2.16.840.1.101.3.4.2.1' in ipa.futureData(certDataLines[loc-2]):
        pertinentAsn1Array.append(ipa.futureData(certDataLines[loc+2]))

# 302010202020 indicates an id of the cert in the file
'''findGroup is the Regex that searches for translated URL, Group, and Action that is nestled in 
    the first few hundred bytes of information in the data messages encoded in the TAMP Message

findCertStarts will be used to split the large data message into smaller information, likely 
    to house a cert

findCertEnds is used to find a likely end for the certificate data.  That substring can then 
    be parsed into an X509 cert using Open SSL
'''
input_data = input_data.hex()
findGroup = re.compile(r'(http.*;\w*)\\x02\\x04')
findCertStarts = re.compile(r'(3412.{3,10}|7420.{2,15})A0820')
findCertEnds = re.compile(r'A1820.{4}2820')
# 0030201020203 indicates an id of the signing cert (30820516308203)
findCertSignerStarts = re.compile(r'(308205.{2}30820.{2,6}003020102020.{8000})')
possibleSignerCerts = findCertSignerStarts.findall(input_data)

signing_cert = ipa.find_signature_cert(possibleSignerCerts)
signing_cert_subject = signing_cert.get_subject().get_components()[-1][1].decode()
print(f'The signing cert subject: {signing_cert_subject}')

count = 0
certAndRawData = []
for pertinentAsn1 in pertinentAsn1Array:
       
    # Prints the group for each signed section
    if len(pertinentAsn1) > 300:
        group = re.search(findGroup, str(codecs.decode(pertinentAsn1[2:300], 'hex')))
        if group:
            url,groupName,store = group.group(1).split(';')
            #print(f'URL: {url}\nGroup: {groupName}\nStore: {store}')

    '''
    Trim off bytes denotation on the front and back of the pertinentAsn1 block and splits
    the larger block into possible certs using the regex
    '''
    possibleCerts = findCertStarts.split(pertinentAsn1[2:-1])
    for miniCertString in possibleCerts:
        try:
            # If the certificate ending regex is found, stop on that byte, else go to end
            searchEnd = re.search(findCertEnds, miniCertString)            
            if searchEnd:
                certBytes = codecs.decode('30820{}'.format(miniCertString[:searchEnd.start()]), 'hex')
            else:
                certBytes = codecs.decode('30820{}'.format(miniCertString), 'hex')
            
            # Load the bytes into a cert, iterate the count and print any information.
            cert = crypto.load_certificate(crypto.FILETYPE_ASN1, certBytes)
            count = count + 1
            certAndRawData.append([cert, certBytes, False if 'Remove' in store else True])
            # Pretty Print whole cert
            #print (crypto.dump_certificate(crypto.FILETYPE_TEXT, cert).decode('utf-8'))
        except Exception as e:
            #print(e)
            pass

windowsStore = []
storeCA = rws.CertStore('CA')
#storeROOT = rws.CertStore('ROOT')
if isWindows:
    try:
        for cert in storeCA.itercerts():
            tempCryptoCert = crypto.load_certificate(crypto.FILETYPE_PEM, cert.get_pem().strip())
            windowsStore.append([tempCryptoCert, 'CA'])
    except Exception as ex:
        print(ex)

for index,irCert in enumerate(certAndRawData):
    for winCert in windowsStore: 
        if winCert[0].digest('sha384') == irCert[0].digest('sha384'):
            certAndRawData[index].append(winCert[1])


print(f'Group: {groupName}')
print(f'URL: {url}')
print(f'This message was signed on: {signingTime}')
print('Subject:{0:<22}Issuer:{0:<33}ID:{0:<6}Action:{0:<7}In Store:'.format(' '))
for certTuple in certAndRawData:
    cert = certTuple[0]
    certSubject = cert.get_subject().get_components()[-1][1].decode()
    certIssuer = cert.get_issuer().get_components()[-1][1].decode()
    certSerialNum = hex(cert.get_serial_number())
    certAction = 'Insert' if certTuple[2] else 'Delete'
    certStore = '--'
    if len(certTuple) > 3:
        certStore = certTuple[3]
    print('{0:<30}{1:<40}{2:<9}{3:<14}{4}'.format(certSubject, certIssuer, certSerialNum, certAction, certStore))

#storeCA.AddCertToStore(certAndRawData[-1][1])

storeCA.close()
del storeCA
storeCA = rws.CertStore('CA')


if isWindows:
    try:
        print(f'Total certs in Windows Store CA: {len(windowsStore)}')
        for winCert in storeCA.itercerts():
            tempCryptoCert = crypto.load_certificate(crypto.FILETYPE_PEM, winCert.get_pem().strip())
            if tempCryptoCert.get_serial_number() == 28:
                print('Located cert with serialNum 28')
                print(winCert.get_name())
                if storeCA.FindCertInStore(winCert):
            #if store.FindCertInStore(winCert[2]) == 'DoD Root CA 3':
                #print(f'{winCert[0].get_serial_number()} #### {int("1c", 16)}')
                    print('Attempting to remove Cert')
                    storeCA.RemoveCert(winCert)
    except Exception as ex:
        print(ex)
        
#storeROOT.close()
storeCA.close()
