const path = require('path');
const x509 = require('../src/x509');
const OID = require('../src/OID');

const fs = require('fs')
const asn1js = require("asn1js");
const pkijs = require("pkijs");
const Extension = pkijs.Extension
const PKIJSCertificate = pkijs.Certificate;

const GoogleCertificatePath = `${path.resolve('./test-data/google.com.cer')}`

test('Some test', () => {})

// test('Non-existant OID should give back the OID number', () => {
//     const commonNameOID = "2.5.4.3"
//     const nonexistantOID = "x.x.x.x"
//     expect(OID.lookup(commonNameOID)).toBe("CN")
//     expect(OID.lookup(nonexistantOID)).toBe(nonexistantOID)
// })

// test('parse google.com.cer into a certificate', () => {
//     const certificate = x509.parse_from_file(GoogleCertificatePath)
//     // console.log(certificate)

//     expect(certificate.version).toBe(2)
//     expect(certificate.serialNumber).toBe(`6e:43:18:b8:d7:90:16:5c:03:00:00:00:00:ba:db:8a`)
//     expect(certificate.signatureAlgorithmId).toBe(`sha256WithRSAEncryption`)
//     expect(certificate.issuer).toBe(`C=US, O=Google Trust Services, CN=GTS CA 1O1`)
//     expect(certificate.validity.notBefore).toBe('2020-11-10T14:34:43.000Z')
//     expect(certificate.validity.notAfter).toBe('2021-02-02T14:34:42.000Z')
//     expect(certificate.subject).toBe('C=US, ST=California, L=Mountain View, O=Google LLC, CN=*.google.com')
//     expect(certificate.signatureValue).toBe('hGqDzsLcYFkG/FCWLV0E7h8cUCxdpnD8ABR7M8bziTV3QqZV9Rvl/n5KwN3Cl4L9wqEMucbOnkc10SqAAFLRZpIvvuXb4Ln4jGJ0p8j3utsem3FJKMKBjBYy8AgPdcO76kmdhp3dumG3y3AAaJ5gG/9R8mDsQ9ZdcJ9JDoEQbFdzCxLlaEPnmd8lht/FpMMzxrUrwFfunc1mxrvlwtwU/V4cL0OVsAATBsT2awFuGqltAKw9YM69Yks+FtKQVrcGMp5ntEsH6k3+1SUGCqXr7heG0DTrjMvvBNpKLgpbLCw0NxziWSpMp928iCtDQnntfg0zUF9IZenv3+r2uR2oiQ==')
//     expect(certificate.extensions.length).toBe(10)
// });











