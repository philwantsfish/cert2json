const certificate = require('../src/certificate');
const path = require('path');
const fs = require('fs');

const GoogleCertificatePath = `${path.resolve('./test-data/google.com.cer')}`
const googleCertificateData = fs.readFileSync(GoogleCertificatePath)

const PinterestInterCertificatePath = `${path.resolve('./test-data/pinterest-interm.pem')}`
const pinterestInterCertificateData = fs.readFileSync(PinterestInterCertificatePath)

const PinterestCertificatePath = `${path.resolve('./test-data/pinterest.pem')}`
const pinterestCertificateData = fs.readFileSync(PinterestCertificatePath)

const TestIpPath = `${path.resolve('./test-data/test-ip.pem')}`
const TestIpData = fs.readFileSync(TestIpPath)

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

test('parseExtension_BasicConstraints', () => {
    const bytes = Buffer.from([0x30, 0x00])
    const tlv = {
        tag: 4,
        tagStr: 'OCTETSTRING',
        len: 2,
        value: bytes,
        lenOfTlv: 4,
        lenOfLen: 1,
        offset: 8,
        parsedResult: { hex: '30:00' }
    }
    const startExtensionObj = {
        "extnID": "X509v3 Basic Constraints",
        "critical": true,
    }
    const extension = certificate.parseExtension_BasicConstraints(startExtensionObj, tlv)

    expected = {
        "extnID": "X509v3 Basic Constraints",
        "critical": true,
        "cA": false
    }

    expect(extension.cA).toBe(expected.cA)
    expect(extension.extnID).toBe(expected.extnID)
    expect(extension.critical).toBe(expected.critical)
})

test('parseExtension_BasicConstraints with cA', () => {
    const bytes = Buffer.from([0x30, 0x06, 0x01, 0x01, 0xff, 0x02, 0x01, 0x00])
    const tlv = {
        tag: 4,
        tagStr: 'OCTETSTRING',
        len: 8,
        value: bytes,
        lenOfTlv: 10,
        lenOfLen: 1,
        offset: 8,
        parsedResult: { hex: '30:06:01:01:ff:02:01:00' }
    }
    const startExtensionObj = {
        "extnID": "X509v3 Basic Constraints",
        "critical": true,
    }
    const extension = certificate.parseExtension_BasicConstraints(startExtensionObj, tlv)

    expected = {
        "extnID": "X509v3 Basic Constraints",
        "critical": true,
        "cA": true
    }

    expect(extension.cA).toBe(expected.cA)
    expect(extension.extnID).toBe(expected.extnID)
    expect(extension.critical).toBe(expected.critical)
    expect(extension.pathLenConstraint).toBe(0)
})

test('parseExtension_CertificatePolicies', () => {
    const bytes = Buffer.from([ 0x30, 0x43, 0x30, 0x37, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xfd, 0x6c, 0x01, 0x01,
                    0x30, 0x2a, 0x30, 0x28, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01, 0x16, 0x1c, 0x68,
                    0x74, 0x74, 0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65,
                    0x72, 0x74, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x43, 0x50, 0x53, 0x30, 0x08, 0x06, 0x06, 0x67, 0x81, 0x0c,
                    0x01, 0x02, 0x02 ])
    const tlv = {
        tag: 4,
        tagStr: 'OCTETSTRING',
        len: 8,
        value: bytes,
        lenOfTlv: 10,
        lenOfLen: 1,
        offset: 8
    }

    const startExtensionObj = {
        "extnID": "X509v3 Certificate Policies",
        "critical": true,
    }
    const extension = certificate.parseExtension_CertificatePolicies(startExtensionObj, tlv)


    expected = {
        "extnID": "X509v3 Certificate Policies",
        "critical": true
    }

    expect(extension.policies.length).toBe(2)
    const policy1 = extension.policies[0]
    expect(policy1.oid).toBe('2.16.840.1.114348.1.1')
    expect(policy1.qualifiers.length).toBe(1)
    expect(policy1.qualifiers[0].oid).toBe('1.3.6.1.5.5.7.2.1')
    expect(policy1.qualifiers[0].str).toBe('https://www.digicert.com/CPS')

    const policy2 = extension.policies[1]
    expect(policy2.oid).toBe('2.23.140.1.2.2')
})

test('Parse a certificate without errors', () => {
    const certificates = [
        googleCertificateData,
        pinterestCertificateData,
        pinterestInterCertificateData,
        TestIpData
    ]

    certificates.forEach(cert => {
        const certificateJson = certificate.parse(cert)

        const certificateString = JSON.stringify(certificateJson)
        expect(certificateString).not.toMatch(/parsedResult/)
    })
})

test('Parse a certificate from files without errors', () => {
    const paths = [
        GoogleCertificatePath,
        PinterestInterCertificatePath,
        PinterestCertificatePath,
        TestIpPath
    ]

    paths.forEach(path => {
        const certificateJson = certificate.parseFromFile(path)

        const certificateString = JSON.stringify(certificateJson)
        expect(certificateString).not.toMatch(/parsedResult/)
    })
})

test('Debugging test that prints a certificate', () => {
    // const cert = certificate.parse(googleCertificateData)
    // const cert = certificate.parsePem(pinterestInterCertificateData)
    // const cert = certificate.parse(pinterestCertificateData)
    // console.log(JSON.stringify(cert, null, 2))
})

test('x', () => {
    // the x509test github project has many test certificates. 
    // try parsing all of these
    // https://github.com/google/x509test/tree/master/tbs
})
