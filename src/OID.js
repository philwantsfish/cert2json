const OID = {
    // OIDs that can be presented when parsing an x509 Issuer field as defined
    // by RFC 5280 -- https://tools.ietf.org/html/rfc5280#section-4.1.2.4
    "2.5.4.3": "CN", // Common Name
    "2.5.4.4": "S", // Surname
    "2.5.4.5": "SN", // Serial Number
    "2.5.4.6": "C", // Country Name
    "2.5.4.7": "L", // Locality Name
    "2.5.4.8": "ST", // State or Province Name
    "2.5.4.10": "O", // Organization Name
    "2.5.4.11": "OU", // Organization Unit
    "2.5.4.12": "T", // Title
    "2.5.4.42": "GN", // Given Name
    "2.5.4.43": "I", // Initials
    "2.5.4.44": "GQ", // Generation Qualifier
    "2.5.4.49": "DN", // Distinguised Name
    "2.5.4.65": "P", // Pseudonym

    // Signature algorithms
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    '1.2.840.10045.2.1': "ecPublicKey",
    '1.2.840.10045.3.1.7': "secp256r1",

    // x509 extensions
    "2.5.29.14": "X509v3 Subject Key Identifier",
    "2.5.29.15": "X509v3 Key Usage",
    "2.5.29.17": "X509v3 Subject Alternative Name", 
    "2.5.29.19": "X509v3 Basic Constraints",
    "2.5.29.31": "X509v3 CRL Distribution Points",
    "2.5.29.32": "X509v3 Certificate Policies",
    "2.5.29.33": "X509v3 Policy Mappings",
    "2.5.29.35": "X509v3 Authority Key Identifier",
    "2.5.29.37": "X509v3 Extended Key Usage",
    "1.3.6.1.5.5.7.1.1": "Authority Information Access",
    "1.3.6.1.5.5.7.3.1": "TLS Web Server Authentication",
    "1.3.6.1.4.1.11129.2.4.2": "1.3.6.1.4.1.11129.2.4.2" // openssl lists this extension as this oid 
}


function lookup(oid) {
    const value = OID[oid]
    if (value === undefined) {
        return oid
    } else {
        return OID[oid]
    }
}


exports.lookup = lookup