const tokenize = require('./der-tokenize')
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
        case TbsTokenOrder.OptionalSubjectUniqueId:
        case TbsTokenOrder.Extensions:
            if (token.tagStr === "cont [ 1 ]") {
                // IssuerUniqueId is identified by context-sensitive tag [1]
                parseIssuerUniqueId(token)
            } else if (token.tagStr === "cont [ 2 ]") {
                // SubjectUniqueId is identified by context-sensitive tag [2]
                parseSubjectUniqueId(token)
            } else if (token.tagStr === "cont [ 3 ]") {
                // Extensions is identified by context-sensitive tag [3]
                return parseExtensions(token)
            }
            throw new Error(`Not supported yet ${tokenOrder}`)
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

function parseExtensions(token) {
    return ["Extensions not supported."]
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

    const parsedTbsTokens = tbsTokens.map((token, i) => {
        return parseTbsToken(i, token)
    })
    const tbs = {
        'version': parsedTbsTokens[TbsTokenOrder.Version],
        'serialNumber': parsedTbsTokens[TbsTokenOrder.SerialNumber],
        'signatureAlgorithm': parsedTbsTokens[TbsTokenOrder.SignatureAlgorithm],
        'issuer': parsedTbsTokens[TbsTokenOrder.Issuer],
        'validity': parsedTbsTokens[TbsTokenOrder.Validity],
        'subject': parsedTbsTokens[TbsTokenOrder.Subject],
        'subjectPublicKeyInfo': parsedTbsTokens[TbsTokenOrder.SubjectPublicKeyInfo],
    }


    const signatureAlgorithm = parseSignatureAlgorithmTokens(signatureAlgorithmTokens)

    // console.log(JSON.stringify(tbs, null, 2))
    // console.log(tbs)

    // console.log(signatureAlgorithm)

    return {
        tbs: tbs,
        signatureAlgorithm: signatureAlgorithm,
        signatureValue: signatureTokens
    }
}



exports.parse = parse