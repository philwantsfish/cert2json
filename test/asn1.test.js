const path = require('path');
const fs = require('fs')
const asn1 = require('../src/asn1')

const GoogleCertificatePath = `${path.resolve('./test-data/google.com.cer')}`
const data = fs.readFileSync(GoogleCertificatePath)

test('asn1 should successfully parse the Google certificate', () => {
    const tokens = asn1.tokenize(data, 0)
    expect(tokens.length).toBe(1)
    expect(tokens[0].tagStr).toBe("SEQUENCE")

    const sequence1 = tokens[0]
    expect(sequence1.parsedResult.length).toBe(3)
    expect(sequence1.parsedResult[0].tagStr).toBe('SEQUENCE')
    expect(sequence1.parsedResult[1].tagStr).toBe('SEQUENCE')
    expect(sequence1.parsedResult[2].tagStr).toBe('BITSTRING')

    const sequence1_2 = sequence1.parsedResult[0]
    expect(sequence1_2.parsedResult.length).toBe(8)

    const sequence1_3 = sequence1.parsedResult[1]
    sequence1_3.parsedResult[0].tagStr = "OBJECT"
    expect(sequence1_3.parsedResult[0].parsedResult).toBe("1.2.840.113549.1.1.11")
    sequence1_3.parsedResult[1].tagStr = "NULL"
})