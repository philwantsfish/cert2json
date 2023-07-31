const DER = require('../src/der');
const asn1 = require('../src/asn1')
const path = require('path');
const fs = require('fs')
const { constants } = require('buffer');

test("Parse a small INTEGER", () => {
    const bytes = [0x2A]
    const byteArray = Buffer.from(bytes)
    const actual = DER.parseInteger(byteArray)
    expect(actual).toBe('42')
})

test("parseInteger 0x00 ", () => {
    const bytes = [0x00]
    const byteArray = Buffer.from(bytes)
    const actual = DER.parseInteger(byteArray)
    expect(actual).toBe('0')
})

test("Parse a large INTEGER", () => {
    const bytes = [0x6E, 0x43, 0x18, 0xB8, 0xD7, 0x90, 0x16, 0x5C, 0x03, 0x00, 0x00, 0x00, 0x00, 0xBA, 0xDB, 0x8A]
    const byteArray = Buffer.from(bytes)
    const actual = DER.parseInteger(byteArray)
    expect(actual).toBe('146563464848388437754251558903598472074')
})

test("Parse a negative INTEGER", () => {
    // TODO
})


test('Shift to leading bits', () => {
    const num1 = DER.shiftToLeadingBits(0x86, 2)
    expect(num1).toBe(0x80)

    const num2 = DER.shiftToLeadingBits(0x86, 3)
    expect(num2).toBe(0xC0)

    const num3 = DER.shiftToLeadingBits(0xf7, 1)
    expect(num3).toBe(0x80)
})

test('getLeadingAndZeroBits', () => {
    const bytes = [0x86, 0xF7, 0x0D]
    const byteArray = Buffer.from(bytes)
    const array = DER.getLeadingAndZeroBits(byteArray)

    const expected = [
        [0x00, 0xFF],
        [0x80, 0x7F],
        [0x80, 0x3F]
    ]

    array.forEach((res, index) => {
        const [m1, m2] = res
        const [expect1, expect2] = expected[index]
        expect(m1).toBe(expect1)
        expect(m2).toBe(expect2)
    })
})

test('Parse Object Identifiers', () => {
    const bytes = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]
    const byteArray = Buffer.from(bytes)
    // const byteArray = Uint8Array.from(bytes).buffer
    // console.log(byteArray)
    const actual = DER.parseObjectIdentifier(byteArray)
    expect(actual).toBe('1.2.840.113549.1.1.11')
})

test('Parse Boolean', () => {
    const bytesFalse = [0x00]
    const bytesTrue = [0xFF]
    
    const expectedTrue = DER.parseBoolean(bytesTrue)
    const expectedFalse = DER.parseBoolean(bytesFalse)

    expect(true).toBe(expectedTrue)
    expect(false).toBe(expectedFalse)
})

test('Parse bitstring with no unused bits', () => {
    const rawBytes = [
        0x00, 0x84, 0x6a, 0x83, 0xce, 0xc2, 0xdc, 0x60, 0x59, 0x06, 0xfc, 0x50, 0x96, 0x2d, 0x5d, 0x04, 0xee, 0x1f, 0x1c,
        0x50, 0x2c, 0x5d, 0xa6, 0x70, 0xfc, 0x00, 0x14, 0x7b, 0x33, 0xc6, 0xf3, 0x89, 0x35, 0x77, 0x42, 0xa6, 0x55, 
        0xf5, 0x1b, 0xe5, 0xfe, 0x7e, 0x4a, 0xc0, 0xdd, 0xc2, 0x97, 0x82, 0xfd, 0xc2, 0xa1, 0x0c, 0xb9, 0xc6, 0xce, 
        0x9e, 0x47, 0x35, 0xd1, 0x2a, 0x80, 0x00, 0x52, 0xd1, 0x66, 0x92, 0x2f, 0xbe, 0xe5, 0xdb, 0xe0, 0xb9, 0xf8, 
        0x8c, 0x62, 0x74, 0xa7, 0xc8, 0xf7, 0xba, 0xdb, 0x1e, 0x9b, 0x71, 0x49, 0x28, 0xc2, 0x81, 0x8c, 0x16, 0x32, 
        0xf0, 0x08, 0x0f, 0x75, 0xc3, 0xbb, 0xea, 0x49, 0x9d, 0x86, 0x9d, 0xdd, 0xba, 0x61, 0xb7, 0xcb, 0x70, 0x00, 
        0x68, 0x9e, 0x60, 0x1b, 0xff, 0x51, 0xf2, 0x60, 0xec, 0x43, 0xd6, 0x5d, 0x70, 0x9f, 0x49, 0x0e, 0x81, 0x10, 
        0x6c, 0x57, 0x73, 0x0b, 0x12, 0xe5, 0x68, 0x43, 0xe7, 0x99, 0xdf, 0x25, 0x86, 0xdf, 0xc5, 0xa4, 0xc3, 0x33, 
        0xc6, 0xb5, 0x2b, 0xc0, 0x57, 0xee, 0x9d, 0xcd, 0x66, 0xc6, 0xbb, 0xe5, 0xc2, 0xdc, 0x14, 0xfd, 0x5e, 0x1c, 
        0x2f, 0x43, 0x95, 0xb0, 0x00, 0x13, 0x06, 0xc4, 0xf6, 0x6b, 0x01, 0x6e, 0x1a, 0xa9, 0x6d, 0x00, 0xac, 0x3d, 
        0x60, 0xce, 0xbd, 0x62, 0x4b, 0x3e, 0x16, 0xd2, 0x90, 0x56, 0xb7, 0x06, 0x32, 0x9e, 0x67, 0xb4, 0x4b, 0x07, 
        0xea, 0x4d, 0xfe, 0xd5, 0x25, 0x06, 0x0a, 0xa5, 0xeb, 0xee, 0x17, 0x86, 0xd0, 0x34, 0xeb, 0x8c, 0xcb, 0xef, 
        0x04, 0xda, 0x4a, 0x2e, 0x0a, 0x5b, 0x2c, 0x2c, 0x34, 0x37, 0x1c, 0xe2, 0x59, 0x2a, 0x4c, 0xa7, 0xdd, 0xbc, 
        0x88, 0x2b, 0x43, 0x42, 0x79, 0xed, 0x7e, 0x0d, 0x33, 0x50, 0x5f, 0x48, 0x65, 0xe9, 0xef, 0xdf, 0xea, 0xf6, 
        0xb9, 0x1d, 0xa8, 0x89
    ]
    const bytes = Buffer.from(rawBytes)

    const bitstring = DER.parseBitString(bytes)
    expect(bitstring.hex).toBe('84:6a:83:ce:c2:dc:60:59:06:fc:50:96:2d:5d:04:ee:1f:1c:50:2c:5d:a6:70:fc:00:14:7b:33:c6:f3:89:35:77:42:a6:55:f5:1b:e5:fe:7e:4a:c0:dd:c2:97:82:fd:c2:a1:0c:b9:c6:ce:9e:47:35:d1:2a:80:00:52:d1:66:92:2f:be:e5:db:e0:b9:f8:8c:62:74:a7:c8:f7:ba:db:1e:9b:71:49:28:c2:81:8c:16:32:f0:08:0f:75:c3:bb:ea:49:9d:86:9d:dd:ba:61:b7:cb:70:00:68:9e:60:1b:ff:51:f2:60:ec:43:d6:5d:70:9f:49:0e:81:10:6c:57:73:0b:12:e5:68:43:e7:99:df:25:86:df:c5:a4:c3:33:c6:b5:2b:c0:57:ee:9d:cd:66:c6:bb:e5:c2:dc:14:fd:5e:1c:2f:43:95:b0:00:13:06:c4:f6:6b:01:6e:1a:a9:6d:00:ac:3d:60:ce:bd:62:4b:3e:16:d2:90:56:b7:06:32:9e:67:b4:4b:07:ea:4d:fe:d5:25:06:0a:a5:eb:ee:17:86:d0:34:eb:8c:cb:ef:04:da:4a:2e:0a:5b:2c:2c:34:37:1c:e2:59:2a:4c:a7:dd:bc:88:2b:43:42:79:ed:7e:0d:33:50:5f:48:65:e9:ef:df:ea:f6:b9:1d:a8:89')
})

test('Parse bitstring with unused bits', () => {
    // TODO 

})

test('Parse all TLVs in a certificate', () => {
    const GoogleCertificatePath = `${path.resolve('./test-data/google.com.cer')}`
    // const path = '../test-data/google.com.cer'
    const data = fs.readFileSync(GoogleCertificatePath)

    // const tlvs = asn1.asn1(data, 0)
    // const parsedTlvs = tlvs.map(tlv => DER.parse(tlv))
    // expect(parsedTlvs.length).toBe(88)

    // Print the parsed TLVs. Leaving here for debugging purposes
    // parsedTlvs.forEach(ptlv => {
    //     console.log(`${ptlv.tag}: ${JSON.stringify(ptlv.parsed)}`)
    // })
})

test('A Sequence with context specific tags', () => {
    // Expecting to parse SEQUENCE[ cont[0], octetstring ]
    const rawBytes = [
        0x30, 0x16, 0x80, 0x14, 0x98, 0xd1, 0xf8, 0x6e, 0x10, 0xeb, 0xcf, 0x9b,
        0xec, 0x60, 0x9f, 0x18, 0x90, 0x1b, 0xa0, 0xeb, 0x7d, 0x09, 0xfd, 0x2b
    ]
    const bytes = Buffer.from(rawBytes)

    const tokens = asn1.tokenize(bytes)
    expect(tokens.length).toBe(1)

    const cont0 = tokens[0].parsedResult
    expect(cont0.length).toBe(1)
    expect(cont0[0].tagStr).toBe('cont [ 0 ]')
})

test("Parsing UTC Time for 30-days month from 31-days one", () => {
  // given
  jest.useFakeTimers().setSystemTime(new Date("2023-07-31T12:00:00Z"));
  const rawBytes = [50, 51, 48, 52, 49, 56, 49, 51, 48, 57, 50, 55, 90];
  const bytes = Buffer.from(rawBytes);

  // when
  const parsedUtcTime = DER.parseUtcTime(bytes);

  // then
  expect(parsedUtcTime).toEqual(new Date("2023-04-18T13:09:27.000Z"));

  jest.useRealTimers();
});

test("Parsing UTC Time for 31-days month from 30-days one", () => {
  // given
  jest.useFakeTimers().setSystemTime(new Date("2023-04-30T12:00:00Z"));

  const rawBytes = [50, 51, 48, 53, 51, 49, 49, 51, 48, 57, 50, 55, 90];
  const bytes = Buffer.from(rawBytes);

  // when
  const parsedUtcTime = DER.parseUtcTime(bytes);

  // then
  expect(parsedUtcTime).toEqual(new Date("2023-05-31T13:09:27.000Z"));

  jest.useRealTimers();
});