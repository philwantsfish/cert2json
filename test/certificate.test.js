const certificate = require('../src/certificate');
const path = require('path');
const fs = require('fs');

const GoogleCertificatePath = `${path.resolve('./test-data/google.com.cer')}`
const data = fs.readFileSync(GoogleCertificatePath)

test('parseVersion', () => {
    const bytes = Buffer.from([ 0x02, 0x01, 0x02 ])
    const tlv = {
        tag: 160,
        tagStr: 'cont [ 0 ]',
        len: 3,
        value: bytes,
        lenOfTlv: 5,
        lenOfLen: 1,
        offset: 0
    }
    const version = certificate.parseVersion(tlv)
    expect(version).toBe(3)
})

test('parseExtension_AuthorityKeyIdentifier', () => {
    const bytes = Buffer.from([0x30, 0x16, 0x80, 0x14, 0x98, 0xd1, 0xf8, 0x6e, 0x10, 0xeb, 0xcf, 0x9b, 0xec, 0x60, 0x9f, 0x18, 0x90, 0x1b, 0xa0, 0xeb, 0x7d, 0x09, 0xfd, 0x2b])

    const tlv = {
        tag: 4,
        tagStr: 'OCTETSTRING',
        len: 24,
        value: bytes,
        lenOfTlv: 26,
        lenOfLen: 1,
        offset: 5,
        parsedResult: {
            hex: '30:16:80:14:98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:7d:09:fd:2b'
        }
    }

    const startExtensionObj = {
        "extnID": "X509v3 Authority Key Identifier",
        "critical": false,
    }
    const extension = certificate.parseExtension_AuthorityKeyIdentifier(startExtensionObj, tlv)

    expected = {
        "extnID": "X509v3 Authority Key Identifier",
        "critical": false,
        "KeyIdentifier": "98:d1:f8:6e:10:eb:cf:9b:ec:60:9f:18:90:1b:a0:eb:7d:09:fd:2b"
    }

    expect(extension.KeyIdentifier).toBe(expected.KeyIdentifier)
    expect(extension.extnID).toBe(expected.extnID)
    expect(extension.critical).toBe(expected.critical)
})

test('parse a certificate', () => {
    const cert = certificate.parse(data)
    // console.log(JSON.stringify(cert, null, 2))
})


// function recurse(tlv) {
//     const parsedResult = tlv.parsedResult
//     if (Array.isArray(parsedResult)) {
//         const arr = []
//         parsedResult.forEach(r => {
//             const item = recurse(r)
//             arr.push(item)
//         })
//         return arr
//     } else {
//         // Not an array, stop recursing
//         return parsedResult
//     }
// }
