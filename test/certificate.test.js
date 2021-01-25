const certificate = require('../src/certificate');
const path = require('path');
const fs = require('fs');

const GoogleCertificatePath = `${path.resolve('./test-data/google.com.cer')}`
const data = fs.readFileSync(GoogleCertificatePath)

test('getVersion', () => {
    // certificate.parse(data)



})

test('parse a certificate', () => {
    const cert = certificate.parse(data)
    console.log(JSON.stringify(cert, null, 2))
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
