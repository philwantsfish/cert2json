const fs = require('fs');
const asn1js = require("asn1js");
const pkijs = require("pkijs");
const PKIJSCertificate = pkijs.Certificate;
const OID = require('./OID');

exports.parse_from_file = parse_from_file
exports.parse = parse

// Parse BER formatted binary data into a Certifiate type from PKIJS
function parse_from_file(path) {
    const data = fs.readFileSync(path)
    const arrayBuffer = new Uint8Array(data).buffer
    return parse(arrayBuffer)
}

// Parse BER formatted binary data into a Certifiate type from PKIJS
function parse(arrayBuffer) {
    const asn1 = asn1js.fromBER(arrayBuffer);
    if(asn1.offset === (-1)) {
        throw new Error("Failed to parse binary data")
    }
    
    const certificate = new PKIJSCertificate({ schema: asn1.result });
    // console.log(JSON.stringify(certificate))
    return new Certificate(certificate)
}

class Certificate {
    // The parsed certificate object from the PKIJS framework
    #pkijsCertificate

    constructor(pkijsCertificate) {
        this.#pkijsCertificate = pkijsCertificate
        this.version = this.#parseVersion()
        this.serialNumber = this.#parseSerialNumber()
        this.signatureAlgorithmId = this.#parseSignatureAlgorithmId()
        this.issuer = this.#parseIssuer()
        this.validity = this.#parseValidity()
        this.subject = this.#parseSubject() 
        this.extensions = this.#parseExtensions()
        this.signatureValue = this.#parseSignatureValue()
    }

    #parseVersion() {
        return this.#pkijsCertificate.version
    }

    #parseSerialNumber() {
        const buffer = this.#pkijsCertificate.serialNumber.valueBlock._valueHex
        // This is a pretty awesoe one-liner copied from SO. The reason we can't create UIntArray
        // from the buffer and call map is because that map function will return another Uint8Array.
        // But inside map we are converting them to strings, so this map function is not applicable.
        // By using the prototype map function we aren't limited to this type. 
        return Array.prototype.map.call(new Uint8Array(buffer), x => ('00' + x.toString(16)).slice(-2)).join(':');
    }


    #parseSignatureAlgorithmId() {
        return OID.lookup(this.#pkijsCertificate.signature.algorithmId)
    }

    #parseIssuer() {
        const oidPairs =this.#pkijsCertificate.issuer.typesAndValues.map(issuerBlock => {
            const oid = OID.lookup(issuerBlock.type)
            const value = issuerBlock.value.valueBlock.value
            return `${oid}=${value}`
        })
        const issuer = oidPairs.join(', ')
        return issuer
    }

    #parseValidity() {
        return {
            "notBefore": this.#pkijsCertificate.notBefore.value.toISOString(),
            "notAfter": this.#pkijsCertificate.notAfter.value.toISOString()
        }
    }

    #parseSubject() {
        const oidPairs =this.#pkijsCertificate.subject.typesAndValues.map(block => {
            const oid = OID.lookup(block.type)
            const value = block.value.valueBlock.value
            return `${oid}=${value}`
        })
        const subject = oidPairs.join(', ')
        return subject
    }

    #parseExtensions() {
        const extensions = []
        // console.log(this.#pkijsCertificate.extensions)
        this.#pkijsCertificate.extensions.forEach(e => {
            // All extensions include these fields
            var extension = {
                oid: e.extnID,
                critical: e.critical,
                name: OID.lookup(e.extnID)
            }

            switch(e.extnID)
            {
            case "2.5.29.9": // SubjectDirectoryAttributes
                // this.parsedValue = new SubjectDirectoryAttributes();
                break;
            case "2.5.29.14": // SubjectKeyIdentifier
                // this.parsedValue = asn1.result; // Should be just a simple OCTETSTRING
                break;
            case "2.5.29.15": // KeyUsage
                // this.parsedValue = asn1.result; // Should be just a simple BITSTRING
                break;
            case "2.5.29.16": // PrivateKeyUsagePeriod
                // this.parsedValue = new PrivateKeyUsagePeriod();
                break;
            case "2.5.29.17": // SubjectAltName
            case "2.5.29.18": // IssuerAltName
                // this.parsedValue = new AltName();
                break;
            case "2.5.29.19": // BasicConstraints
                extension.CA = e.parsedValue.cA
                break;
            case "2.5.29.20": // CRLNumber
            case "2.5.29.27": // BaseCRLNumber (delta CRL indicator)
                // this.parsedValue = asn1.result; // Should be just a simple INTEGER
                break;
            case "2.5.29.21": // CRLReason
                // this.parsedValue = asn1.result; // Should be just a simple ENUMERATED
                break;
            case "2.5.29.24": // InvalidityDate
                // this.parsedValue = asn1.result; // Should be just a simple GeneralizedTime
                break;
            case "2.5.29.28": // IssuingDistributionPoint
                // this.parsedValue = new IssuingDistributionPoint();
                break;
            case "2.5.29.29": // CertificateIssuer
                // this.parsedValue = new GeneralNames();
                break;
            case "2.5.29.30": // NameConstraints
                // this.parsedValue = new NameConstraints();
                break;
            case "2.5.29.31": // CRLDistributionPoints
            case "2.5.29.46": // FreshestCRL
                // this.parsedValue = new CRLDistributionPoints();
                break;
            case "2.5.29.32": // CertificatePolicies
            case "1.3.6.1.4.1.311.21.10": // szOID_APPLICATION_CERT_POLICIES - Microsoft-specific OID
                // this.parsedValue = new CertificatePolicies();
                break;
            case "2.5.29.33": // PolicyMappings
                // this.parsedValue = new PolicyMappings();
                break;
            case "2.5.29.35": // AuthorityKeyIdentifier
                // this.parsedValue = new AuthorityKeyIdentifier();
                break;
            case "2.5.29.36": // PolicyConstraints
                // this.parsedValue = new PolicyConstraints();
                break;
            case "2.5.29.37": // ExtKeyUsage
                // this.parsedValue = new ExtKeyUsage();
                break;
            case "2.5.29.54": // InhibitAnyPolicy
                // this.parsedValue = asn1.result; // Should be just a simple INTEGER
                break;
            case "1.3.6.1.5.5.7.1.1": // AuthorityInfoAccess
            case "1.3.6.1.5.5.7.1.11": // SubjectInfoAccess
                // this.parsedValue = new InfoAccess();
                break;
            case "1.3.6.1.4.1.11129.2.4.2": // SignedCertificateTimestampList
                // this.parsedValue = new SignedCertificateTimestampList();
                break;
            case "1.3.6.1.4.1.311.20.2": // szOID_ENROLL_CERTTYPE_EXTENSION - Microsoft-specific extension
                // this.parsedValue = asn1.result; // Used to be simple Unicode string
                break;
            case "1.3.6.1.4.1.311.21.2": // szOID_CERTSRV_PREVIOUS_CERT_HASH - Microsoft-specific extension
                // this.parsedValue = asn1.result; // Used to be simple OctetString
                break;
            case "1.3.6.1.4.1.311.21.7": // szOID_CERTIFICATE_TEMPLATE - Microsoft-specific extension
                // this.parsedValue = new CertificateTemplate();
                break;
            case "1.3.6.1.4.1.311.21.1": // szOID_CERTSRV_CA_VERSION - Microsoft-specific extension
                // this.parsedValue = new CAVersion();
                break;
            case "1.3.6.1.5.5.7.1.3": // QCStatements
                // this.parsedValue = new QCStatements();
                break;
            default:
            }
            extensions.push(extension)
        })
        return extensions
    }

    #parseSignatureValue() {
        const arrayBuffer = this.#pkijsCertificate.signatureValue.valueBlock.valueHex
        // Convert to buffer so we can call toString('base64')
        const buffer = Buffer.from( new Uint8Array(arrayBuffer) );
        const b64 = buffer.toString('base64')
        return b64
    }
}
