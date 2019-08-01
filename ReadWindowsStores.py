from ctypes import CDLL, c_void_p, POINTER, c_byte, c_long, c_ulong, c_wchar_p, c_char_p, Structure, pointer, string_at, resize, byref, WinDLL, FormatError, cast, create_unicode_buffer
from ctypes.wintypes import LPCWSTR, LPSTR, DWORD, BOOL, BYTE, LPWSTR, LPCSTR, PULONG
import sys
import tempfile
import os
import pdb
import logging


log = logging.getLogger('ReadWindowsStore')


HCERTSTORE = PCCERT_INFO = PCCRL_INFO = c_void_p
LPTCSTR = LPCWSTR

try:
    from ctypes import get_last_error
except ImportError:
    from ctypes import GetLastError as get_last_error
    USE_LAST_ERROR = False
else:
    USE_LAST_ERROR = True

try:
    from base64 import b64encode, b64decode
except ImportError:
    # Python 2.3
    from binascii import b2a_base64

    def b64encode(s):
        return b2a_base64(s)[:-1]


PY3 = sys.version_info[0] == 3

X509_ASN_ENCODING = 0x1
PKCS_7_ASN_ENCODING = 0x00010000
MY_ENCODING = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING

# enhanced key usage
CERT_FIND_EXT_ONLY_ENHKEY_USAGE_FLAG = 0x2
CERT_FIND_PROP_ONLY_ENHKEY_USAGE_FLAG = 0x4
#CRYPT_E_NOT_FOUND = 0x80092004
CRYPT_E_NOT_FOUND = -2146885628

# cert name
CERT_NAME_SIMPLE_DISPLAY_TYPE = 4
CERT_NAME_FRIENDLY_DISPLAY_TYPE = 5
CERT_NAME_ISSUER_FLAG = 0x1

# cert store add
CERT_STORE_ADD_NEW = 1
CERT_STORE_ADD_USE_EXISTING = 2
CERT_STORE_ADD_REPLACE_EXISTING = 3

# cert store find
CERT_COMPARE_EXISTING = 13
CERT_COMPARE_SHIFT = 16
CERT_FIND_EXISTING = CERT_COMPARE_EXISTING << CERT_COMPARE_SHIFT

# cert store open
CERT_STORE_PROV_PHYSICAL = LPCSTR(14)
CERT_STORE_PROV_SYSTEM= LPCSTR(10)
#low
CERT_STORE_OPEN_EXISTING_FLAG = 0x4000
CERT_STORE_READONLY_FLAG = 0x8000
CERT_STORE_DELETE_FLAG = 0x10
#high
CERT_SYSTEM_STORE_CURRENT_USER_ID = 1
CERT_SYSTEM_STORE_LOCAL_MACHINE_ID = 2
CERT_SYSTEM_STORE_CURRENT_SERVICE_ID = 4
CERT_SYSTEM_STORE_SERVICES_ID = 5
CERT_SYSTEM_STORE_USERS_ID = 6
CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID = 7
CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID = 8
CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID = 9
CERT_SYSTEM_STORE_LOCATION_SHIFT = 16

CERT_SYSTEM_STORE_CURRENT_USER = \
    (CERT_SYSTEM_STORE_CURRENT_USER_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
CERT_SYSTEM_STORE_LOCAL_MACHINE = \
    (CERT_SYSTEM_STORE_LOCAL_MACHINE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
CERT_SYSTEM_STORE_CURRENT_SERVICE = \
    (CERT_SYSTEM_STORE_CURRENT_SERVICE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
CERT_SYSTEM_STORE_SERVICES = \
    (CERT_SYSTEM_STORE_SERVICES_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
CERT_SYSTEM_STORE_USERS = \
    (CERT_SYSTEM_STORE_USERS_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY = \
    (CERT_SYSTEM_STORE_CURRENT_USER_GROUP_POLICY_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY = \
    (CERT_SYSTEM_STORE_LOCAL_MACHINE_GROUP_POLICY_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)
CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE = \
    (CERT_SYSTEM_STORE_LOCAL_MACHINE_ENTERPRISE_ID << CERT_SYSTEM_STORE_LOCATION_SHIFT)

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
        err = get_last_error() 
        if err == CRYPT_E_NOT_FOUND:
            return True
        errmsg = FormatError(err)
        raise OSError(err, errmsg)

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

    def get_pCertCtx(self):
        return pointer(self)


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

if USE_LAST_ERROR:
    crypt32 = WinDLL('crypt32.dll', use_last_error=True)
else:
    crypt32 = WinDLL('crypt32.dll')

CertOpenSystemStore = crypt32.CertOpenSystemStoreW
CertOpenSystemStore.argtypes = [c_void_p, LPTCSTR]
CertOpenSystemStore.restype = HCERTSTORE

HCRYPTPROV_LEGACY = PULONG
CertOpenStore = crypt32.CertOpenStore
CertOpenStore.argtypes = [LPCSTR, DWORD, HCRYPTPROV_LEGACY,
                            DWORD, c_void_p]
CertOpenStore.restype = HCERTSTORE

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

CertAddEncodedCertificateToStore = crypt32.CertAddEncodedCertificateToStore
CertAddEncodedCertificateToStore.argtypes = [HCERTSTORE, DWORD, POINTER(BYTE), DWORD,
                                            DWORD, PCCERT_CONTEXT]
CertAddEncodedCertificateToStore.restype = BOOL

CertDeleteCertificateFromStore = crypt32.CertDeleteCertificateFromStore
CertDeleteCertificateFromStore.argtypes= [PCCERT_CONTEXT]
CertDeleteCertificateFromStore.restype = BOOL

CertFindCertificateInStore = crypt32.CertFindCertificateInStore
CertFindCertificateInStore.argtypes = [HCERTSTORE, DWORD, DWORD, DWORD, c_void_p,
                                        PCCERT_CONTEXT]
CertFindCertificateInStore.restype = PCCERT_CONTEXT

CertFreeCertificateContext = crypt32.CertFreeCertificateContext
CertFreeCertificateContext.argtypes = [PCCERT_CONTEXT]
CertFreeCertificateContext.restype = BOOL

CertDuplicateCertificateContext = crypt32.CertDuplicateCertificateContext
CertDuplicateCertificateContext.argtypes = [PCCERT_CONTEXT]
CertDuplicateCertificateContext.restype = PCCERT_CONTEXT

class CertStore(object):
    """Wrapper for Window's cert system store

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
        self._hStore = CertOpenStore(CERT_STORE_PROV_SYSTEM, 0, None,
                CERT_SYSTEM_STORE_LOCAL_MACHINE | CERT_STORE_OPEN_EXISTING_FLAG | 0x1000,
                self._storename)
        if not self._hStore:  # NULL ptr
            self._hStore = None
            errmsg = FormatError(get_last_error())
            raise OSError(errmsg)

    def storename(self):
        """Get store name."""
        return self._storename

    storename = property(storename)

    def close(self):
        """Close a Windows store, checks to make sure all certs are mem freed."""
        success = CertCloseStore(self._hStore, 0x2)
        if success == 0:
            errmsg = FormatError(get_last_error())
            raise OSError(errmsg)
        else:
            log.info(f'Store "{self._storename}" successfully closed')
        self._hStore = None

    def __enter__(self):
        return self

    def __exit__(self, exc, value, tb):
        self.close()

    def itercerts(self, usage=SERVER_AUTH):
        """Iterate over certificates."""
        pCertCtx = CertEnumCertificatesInStore(self._hStore, None)
        while pCertCtx:
            certCtx = pCertCtx[0]
            yield certCtx
            pCertCtx = CertEnumCertificatesInStore(self._hStore, pCertCtx)
        
    def itercrls(self):
        """Iterate over cert revocation lists."""
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

    def AddCertToStore(self, x509cert):
        """Adds a x509 encoded certificate to the Windows store."""
        certLen = len(x509cert)
        certBytes = (c_byte*certLen)(*x509cert)
        success = CertAddEncodedCertificateToStore(self._hStore, X509_ASN_ENCODING,
                certBytes, certLen, CERT_STORE_ADD_NEW, None)
        if success == 0:
            errmsg = FormatError(get_last_error())
            raise OSError(errmsg)

    def FindCertInStore(self, certContext):
        """Returns true if a cert exists in the store."""
        pCcertContext = CertFindCertificateInStore(self._hStore, X509_ASN_ENCODING, 0, 
                        CERT_FIND_EXISTING, certContext.get_pCertCtx(), None)
        if not pCcertContext:
            errmsg = FormatError(get_last_error())
            log.error(errmsg)
            return False
        else:
            CertFreeCertificateContext(pCcertContext)
            return True

    def RemoveCert(self, certContext):
        """Remove a cert from Windows store.

        Arguments:
        certContext -- a CERT_CONTEXT to be deleted

        returns True if successful
        """
        '''Following steps according to:
        https://docs.microsoft.com/en-us/windows/win32/api/wincrypt

        You must first create a duplicate pointer oterwise when deleting the cert
        the pointer loses all reference and the program will crash.

        '''
        dupePointer = CertDuplicateCertificateContext(pointer(certContext))
        success = CertDeleteCertificateFromStore(dupePointer)
        if success == 0:
            errmsg = FormatError(get_last_error())
            raise OSError(errmsg)
        else:
            log.info(f'Successfully removed Cert: {certContext.get_name()}')
            return True
