const tokenize = require('./der-tokenize')
const parser = require('./der-parse')
const OID = require('./OID')

// NOTES
// This file contains the necessary functions to convert the parsed TLV tokens into a Certificate. 

function bytesToHex(bytes) {
    const hex = []
    bytes.slice(1).forEach(b => hex.push(("0" + b.toString(16)).slice(-2)))
    return hex.join(':')
}

const TbsTokenOrder = Object.freeze({
    Version: 0,
    SerialNumber: 1,
    SignatureAlgorithm: 2,
    Issuer: 3,
    Validity: 4,
    Subject: 5,
    SubjectPublicKeyInfo: 6,
    OptionalIssuerUniqueId: 7,
    OptionalSubjectUniqueId: 8,
    Extensions: 9
})

function parseTbsToken(tokenOrder, token) {
    switch (tokenOrder) {
        case TbsTokenOrder.Version:
            return parseVersion(token)
        case TbsTokenOrder.SerialNumber:
            return parseSerialNumber(token)
        case TbsTokenOrder.SignatureAlgorithm:
            return parseSignatureAlgorithm(token)
        case TbsTokenOrder.Issuer:
            return parseIssuer(token)
        case TbsTokenOrder.Validity:
            return parseValidity(token)
        case TbsTokenOrder.Subject:
            return parseSubject(token)
        case TbsTokenOrder.SubjectPublicKeyInfo:
            return parseSubjectPublicKeyInfo(token)
        case TbsTokenOrder.OptionalIssuerUniqueId:
            return parseIssuerUniqueId(token)
        case TbsTokenOrder.OptionalSubjectUniqueId:
            return parseSubjectUniqueId(token)
        case TbsTokenOrder.Extensions:
            return parseExtensions(token)
            // if (token.tagStr === "cont [ 1 ]") {
            //     // IssuerUniqueId is identified by context-sensitive tag [1]
            //     parseIssuerUniqueId(token)
            // } else if (token.tagStr === "cont [ 2 ]") {
            //     // SubjectUniqueId is identified by context-sensitive tag [2]
            //     parseSubjectUniqueId(token)
            // } else if (token.tagStr === "cont [ 3 ]") {
            //     // Extensions is identified by context-sensitive tag [3]
            //     return parseExtensions(token)
            // }
            // throw new Error(`Not supported yet ${tokenOrder}`)
        default:
            const msg = `Error in parseTbsToken. There shouldn't be this many tokens: ${tokenOrder}`
            // console.log(msg)
            // throw new Error(msg)
            return []
    }
}


function parseVersion(token) {
    const version = parseInt(token.parsedResult[0].parsedResult) + 1
    return version
}

function parseSerialNumber(token) {
    const serialNumberInteger = token.parsedResult
    const serialNumberHex = bytesToHex(token.value)
    return {
        int: serialNumberInteger,
        hex: serialNumberHex
    }
}


function parseSignatureAlgorithm(token) {
    const signatureAlgorithmOid = token.parsedResult[0].parsedResult
    const signatureAlgorithm = OID.lookup(signatureAlgorithmOid)
    return {
        oid: signatureAlgorithmOid,
        algo: signatureAlgorithm
    }
}

function parseIssuer(token) {
    const issuerObj = {}

    const parts = token.parsedResult.map(token => {
        const fields = token.parsedResult[0].parsedResult
        const oid =  fields[0].parsedResult
        return {
            oid: oid,
            key: OID.lookup(oid),
            value: fields[1].parsedResult,
        }
    })

    const issuer = parts.map(part => `${part.key}=${part.value}`).join(', ')

    parts.forEach(part => {
        issuerObj[part.key] = part.value
    })
    issuerObj.full = issuer

    return issuerObj
}

function parseValidity(token) {
    const notBefore = token.parsedResult[0].parsedResult
    const notAfter = token.parsedResult[1].parsedResult

    return {
        notBefore: notBefore,
        notAfter: notAfter,
    }
}

function parseSubject(token) {
    const subjectObj = {}

    const parts = token.parsedResult.map(token => {
        const fields = token.parsedResult[0].parsedResult
        const oid = fields[0].parsedResult
        const key = OID.lookup(oid)
        const value = fields[1].parsedResult
        return {
            oid: oid,
            key: key,
            value: value
        }
    })

    const full = parts.map(p => `${p.key}=${p.value}`).join(', ')

    parts.forEach(part => {
        subjectObj[part.key] = part.value
    })
    subjectObj.full = full

    return subjectObj
}

function parseSubjectPublicKeyInfo(token) {
    const subjectPublicKeyInfoParams = token.parsedResult[0].parsedResult.map(t => {
        const oid = t.parsedResult
        const param = OID.lookup(oid)
        return {
            oid: oid,
            param: param
        }
    })
    const subjectPublicKeyInfoKey = token.parsedResult[1].parsedResult.hex
    const subjectPublicKeyInfo = {
        params: subjectPublicKeyInfoParams,
        key: subjectPublicKeyInfoKey
    }
    return subjectPublicKeyInfo
}

function parseIssuerUniqueId(token) {
    throw new Error("Issuer unique id not supported.")
}
function parseSubjectUniqueId(token) {
    throw new Error("Subject unique id not supported.")
}


function parseExtension_AuthorityKeyIdentifier(extensionObj, token) {
    return parser.parseExtension_AuthorityKeyIdentifier(extensionObj, token.value)
}

function parseExtensions(token) {
    const extensionTokens = token.parsedResult[0].parsedResult
    console.log(`[+] ${extensionTokens.length} extension `)
    // console.log(extensionTokens[0])

    const extensions = extensionTokens.map(extensionToken => {
        /**
         * Extensions follow the following format:
         * [
         *  OBJECT
         *  BOOLEAN // optional
         *  OCTETSTRING 
         * ]
         * 
         * The OBJECTs oid indicates the extension
         * The BOOLEAN indicates if the extension is critical
         * The OCTETSTRING contains contextual ASN.1 tokens
         */
        const tokenCount = extensionToken.parsedResult.length

        const oid = extensionToken.parsedResult[0].parsedResult
        const extensionName = OID.lookup(oid)

        var critical = false
        var octetToken
        if (tokenCount === 2) {
            octetToken = extensionToken.parsedResult[1]
        } else {
            critical = extensionToken.parsedResult[1].parsedResult
            octetToken = extensionToken.parsedResult[2]
        }

        // console.log(extensionName)
        var extensionObj = {
            extnID: extensionName,
            critical: critical,
        }
        switch(oid) {
            case "2.5.29.14":
                break
            case "2.5.29.15":
                break
            case "2.5.29.17":
                break
            case "2.5.29.19":
                break
            case "2.5.29.31":
                break
            case "2.5.29.32":
                break
            case "2.5.29.33":
                break
            case "2.5.29.35":
                parseExtension_AuthorityKeyIdentifier(extensionObj, octetToken)
                break
            case "2.5.29.37":
                break
            case "1.3.6.1.5.5.7.1.1":
                break
            case "1.3.6.1.4.1.11129.2.4.2":
                break
            default:
                // nothing
                break
        }
        
        return extensionObj
    })

    // The comments below are quotes pasted from rfc 5280 section 4.2. These are important

    // When an extension appears in a certificate, the OID appears as the field
    // extnID and the corresponding ASN.1 DER encoded structure is the value
    // of the octet string extnValue.

    // An extension includes the boolean critical, with a default value of FALSE.

    // Conforming CAs MUST support key identifiers (Sections 4.2.1.1 and
    // 4.2.1.2), basic constraints (Section 4.2.1.9), key usage (Section
    // 4.2.1.3), and certificate policies (Section 4.2.1.4) extensions.

    // If the CA issues certificates with an empty sequence for the subject
    // field, the CA MUST support the subject alternative name extension
    // (Section 4.2.1.6).


    // At a minimum, applications conforming to this profile MUST recognize
    //    the following extensions: key usage (Section 4.2.1.3), certificate
    //    policies (Section 4.2.1.4), subject alternative name (Section
    //    4.2.1.6), basic constraints (Section 4.2.1.9), name constraints
    //    (Section 4.2.1.10), policy constraints (Section 4.2.1.11), extended
    //    key usage (Section 4.2.1.12), and inhibit anyPolicy (Section
    //    4.2.1.14).
    //    In addition, applications conforming to this profile SHOULD recognize
    //    the authority and subject key identifier (Sections 4.2.1.1 and
    //    4.2.1.2) and policy mappings (Section 4.2.1.5) extensions.

    // extnID is OID
    // value is OCTET string, which is actually a ASN.1 DER encoded struct

    // End of pasting section

    // return ["Extensions not supported."]
    return extensions
}

function parseSignatureAlgorithmTokens(tokens) {
    if (tokens[0].tagStr !== "OBJECT") {
        throw new Error("Expected a OBJECT token when parsing the SignatureAlgorithm")
    }

    const oid = tokens[0].parsedResult
    const algo = OID.lookup(oid)

    tokens.slice(1).map(token => {
        return token.parsedResult
    })

    const params = []

    return {
        oid: oid,
        algo: algo,
        params: params
    }
}

function parse(buffer) {
    const tlvs = tokenize.tokenize(buffer, 0)
    // expect(tlvs.length).toBe(1)

    const certificateTokens = tlvs[0].parsedResult
    // expect(certificateTokens.length).toBe(3)

    const tbsTokens = certificateTokens[0].parsedResult
    const signatureAlgorithmTokens = certificateTokens[1].parsedResult
    const signatureTokens = certificateTokens[2].parsedResult


    // required tbs tokens
    const requiredTokens = tbsTokens.slice(0, TbsTokenOrder.SubjectPublicKeyInfo + 1)

    // optional tokens and extensions
    const optionalTokens = tbsTokens.slice(TbsTokenOrder.OptionalIssuerUniqueId)

    const parsedTbsTokens = requiredTokens.map((token, i) => {
        return parseTbsToken(i, token)
    })

    var tbs = {
        'version': parsedTbsTokens[TbsTokenOrder.Version],
        'serialNumber': parsedTbsTokens[TbsTokenOrder.SerialNumber],
        'signatureAlgorithm': parsedTbsTokens[TbsTokenOrder.SignatureAlgorithm],
        'issuer': parsedTbsTokens[TbsTokenOrder.Issuer],
        'validity': parsedTbsTokens[TbsTokenOrder.Validity],
        'subject': parsedTbsTokens[TbsTokenOrder.Subject],
        'subjectPublicKeyInfo': parsedTbsTokens[TbsTokenOrder.SubjectPublicKeyInfo],
    }

    // Parse the optional fields and extensions
    var issuerUniqueId = undefined
    var subjectUniqueId = undefined
    var extensions = undefined

    optionalTokens.forEach(token => {
        if (token.tagStr === "cont [ 1 ]") {
            // IssuerUniqueId is identified by context-sensitive tag [1]
            issuerUniqueId = parseIssuerUniqueId(token)
        } else if (token.tagStr === "cont [ 2 ]") {
            // SubjectUniqueId is identified by context-sensitive tag [2]
            subjectUniqueId = parseSubjectUniqueId(token)
        } else if (token.tagStr === "cont [ 3 ]") {
            // Extensions is identified by context-sensitive tag [3]
            extensions = parseExtensions(token)
        }
    })

    // Add the optional fields and extensions to the tbs
    if (issuerUniqueId !== undefined) {
        tbs.issuerUniqueId = issuerUniqueId
    }
    if (subjectUniqueId !== undefined) {
        tbs.subjectUniqueId = subjectUniqueId
    }
    if (extensions !== undefined) {
        tbs.extensions = extensions
    }

    const signatureAlgorithm = parseSignatureAlgorithmTokens(signatureAlgorithmTokens)

    return {
        tbs: tbs,
        signatureAlgorithm: signatureAlgorithm,
        signatureValue: signatureTokens
    }
}



exports.parse = parse