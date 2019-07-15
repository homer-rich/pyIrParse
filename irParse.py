import re
import io
import sys
import codecs
import asn1
import ssl
from ctypes import CDLL, c_void_p, POINTER, c_byte, c_long, c_ulong, c_wchar_p, c_char_p, Structure, pointer, string_at, resize
from OpenSSL import crypto
from time import strptime, strftime, gmtime
# ipa houses some functions to print out the asn1 data and prune said data
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
        signingTime = strftime('%B %d %Y %H:%M:%S UTC',  
                strptime(str(ipa.futureData(certDataLines[loc+2])), '%y%m%d%H%M%SZ'))

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

print(f'Group: {groupName}')
print(f'URL: {url}')
print(f'This message was signed on: {signingTime}')
print('Subject:{0:<22}Issuer:{0:<33}ID:{0:<6}Action:{0:<15}'.format(' '))
for certTuple in certAndRawData:
    cert = certTuple[0]
    certSubject = cert.get_subject().get_components()[-1][1].decode()
    certIssuer = cert.get_issuer().get_components()[-1][1].decode()
    certSerialNum = hex(cert.get_serial_number())
    certAction = 'Insert' if certTuple[2] else 'Delete'
#    print('{0:<30}{1:<40}{2:<9}{3:<15}'.format(certSubject, certIssuer, certSerialNum, certAction))

'''
for storename in ("CA", "ROOT"):
    with wincerstore.CertSystemStore(storename) as store:
        for cert in store.itercerts(usage=wincertstore.SERVER_AUTH):
            print(cert.get_pem().decode('ascii'))
            print(cert.get_name())

'''
BYTE = c_byte
BOOL = c_long
DWORD = c_ulong

HCERTSTORE = PCCERT_INFO = PCCRL_INFO = c_void_p
LPTCSTR = LPCWSTR = LPWSTR = c_wchar_p
LPCSTR = LPSTR = c_char_p

USE_LAST_ERROR = True

try:
    from base64 import b64encode
except ImportError:
    # Python 2.3
    from binascii import b2a_base64

    def b64encode(s):
        return b2a_base64(s)[:-1]


PY3 = sys.version_info[0] == 3

PKCS_7_ASN_ENCODING = 0x00010000

# enhanced key usage
CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG = 0x2
CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG = 0x4
#CRYPT_E_NOT_FOUND = 0x80092004
CRYPT_E_NOT_FOUND = -2146885628

# cert name
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_NAME_FRIENDLY_DISPLAY_TYPE = 5
CERT_NAME_ISSUER_FLAG = 0x1

# OID mapping for enhanced key usage
SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
CLIENT_AUTH = "1.3.6.1.5.5.7.3.2"
CODE_SIGNING = "1.3.6.1.5.5.7.3.3"
EMAIL_PROTECTION = "1.3.6.1.5.5.7.3.4"
IPSEC_END_SYSTEM = "1.3.6.1.5.5.7.3.5"
IPSEC_TUNNEL = "1.3.6.1.5.5.7.3.6"
IPSEC_USER = "1.3.6.1.5.5.7.3.7"
TIME_STAMPING = "1.3.6.1.5.5.7.3.8"
OCSP_SIGNING = "1.3.6.1.5.5.7.3.9"
DVCS = "1.3.6.1.5.5.7.3.10"

TrustOIDs = {
    SERVER_AUTH: "SERVER_AUTH",
    CLIENT_AUTH: "CLIENT_AUTH",
    CODE_SIGNING: "CODE_SIGNING",
    EMAIL_PROTECTION: "EMAIL_PROTECTION",
    IPSEC_END_SYSTEM: "IPSEC_END_SYSTEM",
    IPSEC_TUNNEL: "IPSEC_TUNNEL",
    IPSEC_USER: "IPSEC_USER",
    TIME_STAMPING: "TIME_STAMPING",
    OCSP_SIGNING: "OCSP_SIGNING",
    DVCS: "DVCS",
}


def isPKCS7(value):
    """PKCS#7 check
    """
    return (value & PKCS_7_ASN_ENCODING) == PKCS_7_ASN_ENCODING


class ContextStruct(Structure):
    cert_type = None
    __slots__ = ()
    _fields_ = []

    def get_encoded(self):
        """Get encoded cert as byte string
        """
        pass

    def encoding_type(self):
        """Get encoding type for PEM
        """
        if isPKCS7(self.dwCertEncodingType):
            return "PKCS7"
        else:
            return self.cert_type

    encoding_type = property(encoding_type)

    def get_pem(self):
        """Get PEM encoded cert
        """
        encoding_type = self.encoding_type
        b64data = b64encode(self.get_encoded()).decode("ascii")
        lines = ["-----BEGIN %s-----" % encoding_type]
        # split up in lines of 64 chars each
        quotient, remainder = divmod(len(b64data), 64)
        linecount = quotient + bool(remainder)
        for i in range(linecount):
            lines.append(b64data[i * 64:(i + 1) * 64])
        lines.append("-----END %s-----" % encoding_type)
        # trailing newline
        lines.append("")
        return "\n".join(lines)


class CERT_CONTEXT(ContextStruct):
    """Cert context
    """
    cert_type = "CERTIFICATE"
    __slots__ = ("_enhkey")
    _fields_ = [
        ("dwCertEncodingType", DWORD),
        ("pbCertEncoded", POINTER(BYTE)),
        ("cbCertEncoded", DWORD),
        ("pCertInfo", PCCERT_INFO),
        ("hCertStore", HCERTSTORE),
        ]

    def get_encoded(self):
        return string_at(self.pbCertEncoded, self.cbCertEncoded)

    def _enhkey_error(self):
        return True
        #err = True 
        #if err == CRYPT_E_NOT_FOUND:
        #    return True
        # errmsg = FormatError(err)
        #raise OSError(err, errmsg)
        raise Exception('Oh no!')

    def _get_enhkey(self, flag):
        pCertCtx = pointer(self)
        enhkey = CERT_ENHKEY_USAGE()
        size = DWORD()

        res = CertGetEnhancedKeyUsage(pCertCtx, flag, None, pointer(size))
        if res == 0:
            return self._enhkey_error()

        resize(enhkey, size.value)
        res = CertGetEnhancedKeyUsage(pCertCtx, flag, pointer(enhkey),
                                      pointer(size))
        if res == 0:
            return self._enhkey_error()

        oids = set()
        for i in range(enhkey.cUsageIdentifier):
            oid = enhkey.rgpszUsageIdentifier[i]
            if oid:
                if PY3:
                    oid = oid.decode("ascii")
                oids.add(oid)
        return oids

    def enhanced_keyusage(self):
        enhkey = getattr(self, "_enhkey", None)
        if enhkey is not None:
            return enhkey
        keyusage = self._get_enhkey(CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG)
        if keyusage is True:
            keyusage = self._get_enhkey(CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG)
        if keyusage is True:
            self._enhkey = True
        else:
            self._enhkey = frozenset(keyusage)
        return keyusage

    def enhanced_keyusage_names(self):
        enhkey = self.enhanced_keyusage()
        if enhkey is True:
            return True
        result = set()
        for oid in self.enhanced_keyusage():
            result.add(TrustOIDs.get(oid, oid))
        return result

    def get_name(self, typ=CERT_NAME_SIMPLE_DISPLAY_TYPE, flag=0):
        pCertCtx = pointer(self)
        cbsize = CertGetNameStringW(pCertCtx, typ, flag, None, None, 0)
        buf = create_unicode_buffer(cbsize)
        cbsize = CertGetNameStringW(pCertCtx, typ, flag, None, buf, cbsize)
        return buf.value


class CRL_CONTEXT(ContextStruct):
    """Cert revocation list context
    """
    cert_type = "X509 CRL"
    __slots__ = ()
    _fields_ = [
        ("dwCertEncodingType", DWORD),
        ("pbCrlEncoded", POINTER(BYTE)),
        ("cbCrlEncoded", DWORD),
        ("pCrlInfo", PCCRL_INFO),
        ("hCertStore", HCERTSTORE),
        ]

    def get_encoded(self):
        return string_at(self.pbCrlEncoded, self.cbCrlEncoded)


class CERT_ENHKEY_USAGE(Structure):
    """Enhanced Key Usage
    """
    __slots__ = ()
    _fields_ = [
        ("cUsageIdentifier", DWORD),
        ("rgpszUsageIdentifier", POINTER(LPSTR))
        ]

crypt32 = CDLL('crypt32.dll', use_last_error=True)

CertOpenSystemStore = crypt32.CertOpenSystemStoreW
CertOpenSystemStore.argtypes = [c_void_p, LPTCSTR]
CertOpenSystemStore.restype = HCERTSTORE

CertCloseStore = crypt32.CertCloseStore
CertCloseStore.argtypes = [HCERTSTORE, DWORD]
CertCloseStore.restype = BOOL

PCCERT_CONTEXT = POINTER(CERT_CONTEXT)
CertEnumCertificatesInStore = crypt32.CertEnumCertificatesInStore
CertEnumCertificatesInStore.argtypes = [HCERTSTORE, PCCERT_CONTEXT]
CertEnumCertificatesInStore.restype = PCCERT_CONTEXT

PCCRL_CONTEXT = POINTER(CRL_CONTEXT)
CertEnumCRLsInStore = crypt32.CertEnumCRLsInStore
CertEnumCRLsInStore.argtypes = [HCERTSTORE, PCCRL_CONTEXT]
CertEnumCRLsInStore.restype = PCCRL_CONTEXT

PCERT_ENHKEY_USAGE = POINTER(CERT_ENHKEY_USAGE)
CertGetEnhancedKeyUsage = crypt32.CertGetEnhancedKeyUsage
CertGetEnhancedKeyUsage.argtypes = [PCCERT_CONTEXT, DWORD, PCERT_ENHKEY_USAGE,
                                    POINTER(DWORD)]
CertGetEnhancedKeyUsage.restype = BOOL

CertGetNameStringW = crypt32.CertGetNameStringW
CertGetNameStringW.argtypes = [PCCERT_CONTEXT, DWORD, DWORD, c_void_p,
                               LPWSTR, DWORD]
CertGetNameStringW.restype = DWORD

class CertSystemStore(object):
    """Wrapper for Window's cert system store

    http://msdn.microsoft.com/en-us/library/windows/desktop/aa376560%28v=vs.85%29.aspx

    store names
    -----------
    CA:
      Certification authority certificates
    MY:
      Certs with private keys
    ROOT:
      Root certificates
    SPC:
      Software Publisher Certificate
    """
    __slots__ = ("_storename", "_hStore")

    def __init__(self, storename):
        self._storename = storename
        self._hStore = CertOpenSystemStore(None, self.storename)
        if not self._hStore:  # NULL ptr
            self._hStore = None
            # errmsg = FormatError(err)
            #raise OSError(err, errmsg)
            raise Exception('Oh no!')

    def storename(self):
        """Get store name
        """
        return self._storename

    storename = property(storename)

    def close(self):
        CertCloseStore(self._hStore, 0)
        self._hStore = None

    def __enter__(self):
        return self

    def __exit__(self, exc, value, tb):
        self.close()

    def itercerts(self, usage=SERVER_AUTH):
        """Iterate over certificates
        """
        pCertCtx = CertEnumCertificatesInStore(self._hStore, None)
        while pCertCtx:
            certCtx = pCertCtx[0]
            enhkey = certCtx.enhanced_keyusage()
            if usage is not None:
                if enhkey is True or usage in enhkey:
                    yield certCtx
            else:
                yield certCtx
            pCertCtx = CertEnumCertificatesInStore(self._hStore, pCertCtx)

    def itercrls(self):
        """Iterate over cert revocation lists
        """
        pCrlCtx = CertEnumCRLsInStore(self._hStore, None)
        while pCrlCtx:
            crlCtx = pCrlCtx[0]
            yield crlCtx
            pCrlCtx = CertEnumCRLsInStore(self._hStore, pCrlCtx)

    def __iter__(self):
        for cert in self.itercerts():
            yield cert
        for crl in self.itercrls():
            yield crl


class CertFile(object):
    """Wrapper to handle a temporary file for a CA.pem

    Note: The object uses a temporary file because older Python versions have
          no means to keep a tempfile after it has been closed.

    Usage:
        import wincertstore
        import atexit

        certfile = wincertstore.CertFile()
        certfile.addstore("CA")
        certfile.addstore("ROOT")
        atexit.register(certfile.close) # cleanup and remove files on shutdown)

        ca_cert = certfile.name

    """

    def __init__(self, suffix="certstore"):
        self._tempdir = tempfile.mkdtemp(suffix=suffix)
        self._capem = os.path.join(self._tempdir, "ca.pem")

    def name(self):
        """Path to CA.pem
        """
        return self._capem

    name = property(name)

    def close(self):
        shutil.rmtree(self._tempdir)
        self._tempdir = None
        self._capem = None

    def __enter__(self):
        return self

    def __exit__(self, exc, value, tb):
        self.close()

    def addcerts(self, certs):
        """Add certs to store
        """
        f = open(self._capem, "a")
        try:
            #f.seek(0, os.SEEK_END)
            for cert in certs:
                f.write(cert.get_pem())
        finally:
            f.close()

    def addstore(self, store):
        """Add store to CertFile

        :param store: either a name of a store or a CertSystemStore instance
        """
        if hasattr(store, "itercerts"):
            self.addcerts(store.itercerts())
        else:
            store = CertSystemStore(store)
            try:
                self.addcerts(store.itercerts())
            finally:
                store.close()

    def read(self):
        """Read CA.pem file and return content
        """
        f = open(self._capem, "r")
        try:
            return f.read()
        finally:
            f.close()

windowsStore = []
for storename in ("CA", "ROOT"):
    store = CertSystemStore(storename)
    try:
        for cert in store.itercerts():
            windowsStore.append(crypto.load_certificate(crypto.FILETYPE_PEM, cert.get_pem().strip()))
            # print(cert.get_pem().strip())
    finally:
        store.close()

for winCert in windowsStore:
    print(winCert.get_subject())
