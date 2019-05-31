import io
import sys
import asn1
import codecs
from time import strptime, strftime, gmtime


def pretty_print(input_stream, output_stream, indent=0):
    """Pretty print ASN.1 data."""
    while not input_stream.eof():
        tag = input_stream.peek()
        if tag.typ == asn1.Types.Primitive:
            tag, value = input_stream.read()
            output_stream.write(' ' * indent)
            output_stream.write('[{}] {}: {}\n'.format(class_id_to_string(tag.cls), tag_id_to_string(tag.nr), value_to_string(tag.nr, value, indent, output_stream, tag.cls)))
            # output_stream.write('{}\n'.format(value_to_string(tag.nr, value, indent, output_stream)))
        elif tag.typ == asn1.Types.Constructed:
            output_stream.write(' ' * indent)
            output_stream.write('[{}] {}\n'.format(class_id_to_string(tag.cls), tag_id_to_string(tag.nr)))
            input_stream.enter()
            pretty_print(input_stream, output_stream, indent + 2)
            input_stream.leave()


tag_id_to_string_map = {
    asn1.Numbers.Boolean: "BOOLEAN",
    asn1.Numbers.Integer: "INTEGER",
    asn1.Numbers.BitString: "BIT STRING",
    asn1.Numbers.OctetString: "OCTET STRING",
    asn1.Numbers.Null: "NULL",
    asn1.Numbers.ObjectIdentifier: "OBJECT",
    asn1.Numbers.PrintableString: "PRINTABLESTRING",
    asn1.Numbers.IA5String: "IA5STRING",
    asn1.Numbers.UTCTime: "UTCTIME",
    asn1.Numbers.Enumerated: "ENUMERATED",
    asn1.Numbers.Sequence: "SEQUENCE",
    asn1.Numbers.Set: "SET",
    asn1.Numbers.UTF8String: "UTF8 STRING"
}

class_id_to_string_map = {
    asn1.Classes.Universal: "U",
    asn1.Classes.Application: "A",
    asn1.Classes.Context: "C",
    asn1.Classes.Private: "P"
}

object_id_to_string_map = {
    "2.5.4.3": "commonName",
    "2.5.4.4": "surname",
    "2.5.4.5": "serialNumber",
    "2.5.4.6": "countryName",
    "2.5.4.7": "localityName",
    "2.5.4.8": "stateOrProvinceName",
    "2.5.4.9": "streetAddress",
    "2.5.4.10": "organizationName",
    "2.5.4.11": "organizationalUnitName",
    "2.5.4.12": "title",
    "2.5.4.13": "description",
    "2.5.4.42": "givenName",

    "2.5.29.14": "X509v3 Subject Key Identifier",
    "2.5.29.15": "X509v3 Key Usage",
    "2.5.29.16": "X509v3 Private Key Usage Period",
    "2.5.29.17": "X509v3 Subject Alternative Name",
    "2.5.29.18": "X509v3 Issuer Alternative Name",
    "2.5.29.19": "X509v3 Basic Constraints",
    "2.5.29.30": "X509v3 Name Constraints",
    "2.5.29.31": "X509v3 CRL Distribution Points",
    "2.5.29.32": "X509v3 Certificate Policies Extension",
    "2.5.29.33": "X509v3 Policy Mappings",
    "2.5.29.35": "X509v3 Authority Key Identifier",
    "2.5.29.36": "X509v3 Policy Constraints",
    "2.5.29.37": "X509v3 Extended Key Usage",

    "1.3.14.3.2.26": "hashAlgorithmIdentifier",

    "1.3.6.1.5.5.7.1.1": "authorityInfoAccess",
    "1.3.6.1.5.5.7.3.9": "id-kp-OCSPSigning",
    "1.3.6.1.5.5.7.48.2": "caIssuers",
    "1.3.6.1.5.5.7.48.1.1": "basic-response",
    "1.3.6.1.5.5.7.48.1.2": "nonce-extension",
    "1.3.6.1.5.5.7.48.1.3": "crl",
    "1.3.6.1.5.5.7.48.1.5": "no-check",

    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.3": "md4WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1-with-rsa-signature",
    "1.2.840.113549.1.1.6": "rsaOAEPEncryption",
    "1.2.840.113549.1.1.7": "id-RSAES-OAEP",
    "1.2.840.113549.1.1.8": "id-mgfl",
    "1.2.840.113549.1.1.9": "id-pSpecified",
    "1.2.840.113549.1.1.10": "rsassa-pss",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",    
    "1.2.840.113549.1.9.1": "emailAddress",

    "2.16.840.1.101.3.2.1.3.1": "id-fpki-certpcy-rudimentaryAssurance",
    "2.16.840.1.101.3.2.1.3.2": "id-fpki-certpcy-basicAssurance",
    "2.16.840.1.101.3.2.1.3.3": "id-fpki-certpcy-mediumAssurance",
    "2.16.840.1.101.3.2.1.3.4": "id-fpki-certpcy-highAssurance",
    "2.16.840.1.101.3.2.1.3.5": "id-fpki-certpcy-testAssurance",
    "2.16.840.1.101.3.2.1.3.6": "id-fpki-common-policy",
    "2.16.840.1.101.3.2.1.3.7": "id-fpki-common-hardware",
    "2.16.840.1.101.3.2.1.3.8": "id-fpki-common-devices",
    "2.16.840.1.101.3.2.1.3.12": "id-fpki-certpcy-mediumHardware",
    "2.16.840.1.101.3.2.1.3.13": "id-fpki-common-authentication",
    "2.16.840.1.101.3.2.1.3.14": "id-fpki-certpcy-medium-CBP",
    "2.16.840.1.101.3.2.1.3.15": "id-fpki-certpcy-mediumHW-CBP",
    "2.16.840.1.101.3.2.1.3.16": "id-fpki-common-high",
    "2.16.840.1.101.3.2.1.3.17": "id-fpki-common-cardAuth",
    "2.16.840.1.101.3.2.1.3.18": "id-fpki-certpcy-pivi-hardware",
    "2.16.840.1.101.3.2.1.3.19": "id-fpki-certpcy-pivi-cardAuth",
    "2.16.840.1.101.3.2.1.3.20": "id-fpki-certpcy-pivi-contentSigning",
    "2.16.840.1.101.3.2.1.3.39": "id-fpki-common-piv-contentSigning",
    "2.16.840.1.101.3.2.1.3.40": "id-fpki-common-derived-pivAuth",

    # Verified from https://iase.disa.mil/pki-pke/Documents/unclass-dod_cp_v10-5.pdf
    "2.16.840.1.101.2.1.11.2": "id-US-dod-basic",
    "2.16.840.1.101.2.1.11.4": "id-US-dod-FORTEZZA",
    "2.16.840.1.101.2.1.11.5": "id-US-dod-medium",
    "2.16.840.1.101.2.1.11.6": "id-US-dod-type1",
    "2.16.840.1.101.2.1.11.9": "id-US-dod-mediumHardware",
    "2.16.840.1.101.2.1.11.10": "id-US-dod-PIV-Auth",
    "2.16.840.1.101.2.1.11.17": "id-US-dod-mediumNPE",
    "2.16.840.1.101.2.1.11.18": "id-US-dod-medium-2048",
    "2.16.840.1.101.2.1.11.19": "id-US-dod-mediumHardware-2048",
    "2.16.840.1.101.2.1.11.20": "id-US-dod-PIV-Auth-2048",
    "2.16.840.1.101.2.1.11.31": "id-US-dod-peerInterop",
    "2.16.840.1.101.2.1.11.36": "id-US-dod-mediumNPE-112",
    "2.16.840.1.101.2.1.11.37": "id-US-dod-mediumNPE-128",
    "2.16.840.1.101.2.1.11.39": "id-US-dod-medium-112",
    "2.16.840.1.101.2.1.11.40": "id-US-dod-medium-128",
    "2.16.840.1.101.2.1.11.42": "id-US-dod-mediumHardware-112",
    "2.16.840.1.101.2.1.11.43": "id-US-dod-mediumHardware-128"
    
}


def tag_id_to_string(identifier):
    """Return a string representation of a ASN.1 id."""
    if identifier in tag_id_to_string_map:
        return tag_id_to_string_map[identifier]
    return '{:#02x}'.format(identifier)


def class_id_to_string(identifier):
    """Return a string representation of an ASN.1 class."""
    if identifier in class_id_to_string_map:
        return class_id_to_string_map[identifier]
    raise ValueError('Illegal class: {:#02x}'.format(identifier))


def object_identifier_to_string(identifier):
    if identifier in object_id_to_string_map:
        return object_id_to_string_map[identifier]
    return identifier

def value_to_string(tag_number, value, indent, output_stream, tag_class):
    if tag_number == asn1.Numbers.ObjectIdentifier:
        if tag_class == asn1.Classes.Context:
            asciiList = value.split('.')
            charList = []
            for ch in asciiList:
                charList.append(chr(int(ch)))
            return 'h{}'.format(''.join(charList[2:]))
        else:
            return object_identifier_to_string(value)
    elif tag_number == asn1.Numbers.OctetString:
        octDecoder = asn1.Decoder()
        octDecoder.start(value)
        try:
            pretty_print(octDecoder, output_stream, indent)
        except:
            try:
                return codecs.decode(value, "ascii")
            except:
                return value.hex()
            
    elif tag_number == asn1.Numbers.UTF8String:
        try:
            return codecs.decode(value, "ascii")
        except:
            return 'Failed UTF8: {}'.format(value)
    elif tag_number == asn1.Numbers.Integer:
        return hex(value)
    elif tag_number == asn1.Numbers.UTCTime:
        return strftime('%B %d %Y %H:%M:%S UTC', strptime(str(value), "%y%m%d%H%M%SZ"))
    elif isinstance(value, bytes):
        return value.hex().upper()
    elif isinstance(value, str):
        return value
    else:
        return repr(value)



