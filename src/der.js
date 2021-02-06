const Constants = require('./constants')
const TagTypes = Constants.TagTypes
const hex2dec = require('./hex2dec')
const utils = require('./utils')

// NOTES
// The asn1 file converts the binary blob (certificate) into TLV tokens. The value (V) of those tokens is still binary at this point.
// These functions parse those small binary blobs into meaningful types: Boolean, Integer, UTCTime, and so on.  


function parseInteger(value) {
    // if the leading bit if set, then its in 2s complement form
    if ((value[0] & 80) === 1) {
        throw new Error("No support for 2s complement number yet")
    } else {
        // Convert the bytes into a hex string
        let hex = Buffer.from(value).toString('hex');

        // If we want decimal representation, then use the following high precision converter. 
        // The builtin parseInt(value, 16) will not work with larger numbers (>60 bytes).  
        const dec = hex2dec.hexToDec(hex)

        return dec
    }
}

function isLeadingBitSet(byte) {
    return (byte & 0x80) === 0x80
}

function hexByteToDecimal(byte) {
    const hex = byte.toString(16)
    const decimal = hex2dec.hexToDec(hex) 
    return decimal

}

function parsePrintableString(value) {
    return value.toString()
}

function parseIA5String(value) {
    return value.toString()
}


// Returns a new Uint8 number where the first {num} bits are set from the last N bits of {byte}
function shiftToLeadingBits(byte, num) {
    var byteCopy = byte
    var newByte = 0x00
    for (i = 0; i < num; i++) {
        newByte = newByte >> 1
        // If the LSB bit is 1, set the leading bit
        if ((byteCopy & 0x01) === 0x01) {
            newByte = newByte | 0x80
        }

        // Shfit the byte to analyze the next
        byteCopy = byteCopy >> 1
    }
    return newByte
}

// OID are encoded with a algorithm described here https://docs.microsoft.com/en-us/windows/win32/seccertenroll/about-object-identifier
// This function returns an array with two bit masks. The first is the bits to set in each byte, the
// second is the bits to zero in each byte. 
function getLeadingAndZeroBits(bytes) {
    var leadingBits = [  ]
    bytes.slice(0, -1).map((b,index) => {
        // Keep the right n bits
        const n = bytes.length - index - 1
        const contextualMask = shiftToLeadingBits(b, n)
        leadingBits.push([
            contextualMask,
            0xFF >> n
        ])
    })
    leadingBits.push([0x00, 0xFF])
    leadingBits = leadingBits.reverse()

    return leadingBits
}

function getObjectIdentifierLen(bytes, offset) {
    // This means the number uses multiple bytes. 
    // The length of the object identifier is determined using the leading bit. Continue using bytes until the leading bit is not set
    var len = 1 
    while( isLeadingBitSet(bytes.readUInt8(offset + len))) { // && (offset + len) <= value.length) {
        len = len + 1
    }
    len = len + 1
    return len

}

function parseObjectIdentifier(value) {
    const headNumber = hexByteToDecimal(value.readUInt8(0))
    const parsedHead = [
        Math.trunc(headNumber / 40), // remove decimal
        headNumber % 40
    ]

    var offset = 1
    var parsedTail = []
    while (offset < value.length) {
        const b = value.readUInt8(offset)
        if (isLeadingBitSet(b)) {
            const len = getObjectIdentifierLen(value, offset)

            // If we've continued reading past the end of the value, then we've hit some malformed situation.
            if ((offset + len) > value.length) {
                throw new Error("Malformed object identifier.")
            }

            // These bytes make up the object identifier
            var idBytes = value.slice(offset, offset + len)

            // Calculate the bit masks to apply to each byte
            const masks = getLeadingAndZeroBits(idBytes)

            // Apply the algorithm to the bytes
            // 1) Zero leading bit
            // 2) Mask first N bits
            // 3) Shift N bits to the right
            // 4) Set first N bits
            const parsedBytes = idBytes.map((b,index) => {
                var tmpByte = b
                const [maskWithBits, maskWithZeros] = masks[index]
                const hasLeadingBit = isLeadingBitSet(tmpByte)
                tmpByte = tmpByte & 0x7F

                // zero out n bits
                tmpByte = tmpByte & maskWithZeros
                if (hasLeadingBit) {
                    // shift n bits
                    tmpByte = tmpByte >>> (idBytes.length - 1 - index)
                }
                tmpByte = tmpByte | maskWithBits
                return tmpByte
            })

            // Convert to string and save
            let hex = Buffer.from(parsedBytes).toString('hex');
            const dec = hex2dec.hexToDec(hex)
            parsedTail.push(dec)

            // Update the offset the appropriate length
            offset = offset + len
        } else {
            // Convert to string, then to decimal
            parsedTail.push(hexByteToDecimal(b))
            offset = offset + 1
        }
    }

    const result = parsedHead.concat(parsedTail).join('.')
    return result

}

function parseBoolean(bytes) {
    const T = 0xFF
    const F = 0x00
    if (bytes.length != 1 || ![T, F].includes(bytes[0]) ) {
        throw new Error("Malformed boolean", bytes)
    }
    
    return bytes[0] === T ? true : false
}

function parseBitString(bytes) {
    const unusedBits = bytes.readUInt8(0)
    if (unusedBits == 0x00) {
        // same logic as octet string here? call that?
        const hex = []
        bytes.slice(1).forEach(b => hex.push(("0" + b.toString(16)).slice(-2)))
        return {
            hex: hex.join(":")
        }
    } else {
        throw new Error("TODO: Handle unsued bits for bit string")
    }
}

function parseOctetString(bytes) {
    return {
        hex: utils.bytesToHex(bytes)
    }
}

function parseUtcTime(bytes) {
    const dateString = bytes.toString()

    // Get the values from the string which is in format 'YYMMDDHHMMSSZ'
    const yearDigits = dateString.substring(0, 2)
    const month = dateString.substring(2, 4)
    const day = dateString.substring(4, 6)
    const hour = dateString.substring(6, 8)
    const min = dateString.substring(8, 10)
    const sec = dateString.substring(10, 12)

    // We're given 2 year digits. If they are over 50 then its 19xx, under 50 is 20xx (RFC 5280)
    var year;
    if (yearDigits >= 50) {
        year = `19${yearDigits}`
    } else {
        year = `20${yearDigits}`
    }


    // Create a date object and set the values for GMT/UTC
    const d = new Date()
    d.setUTCFullYear(year)
    d.setUTCMonth(month - 1) // Javascript quirk, month is the only one that is zero indexed
    d.setUTCDate(day)
    d.setUTCHours(hour)
    d.setUTCMinutes(min)
    d.setUTCSeconds(sec)
    d.setUTCMilliseconds(0)

    return d
}

function parseGeneralizedTime(bytes) {
    throw new Error("Token type GeneralizedTime not supported")
}

function parseUtf8String(bytes) {
    return bytes.toString()
}

function parseSequence(bytes) {
    console.log(`[+] !!! hERE !!!`)

    return []
}
function parseSet(bytes) {
    return []
}

function parseNull(bytes) {
    return null
}

const tagToParseFunctionMap = {
    PRINTABLESTRING: parsePrintableString,
    INTEGER: parseInteger,
    OBJECT: parseObjectIdentifier,
    BITSTRING: parseBitString,
    OCTETSTRING: parseOctetString,
    UTCTIME: parseUtcTime,
    GENERALIZEDTCTIME: parseGeneralizedTime,
    UTF8STRING: parseUtf8String,
    IA5STRING: parseIA5String,
    SEQUENCE: parseSequence,
    SET: parseSet,
    NULL: parseNull,
    BOOLEAN: parseBoolean
}

function getParsingFunction(tagString) {
    return tagToParseFunctionMap[tagString]
}

// Given a TLV, parse the value
function parse(tlv) {
    // console.log(`[+] tlv`, tlv)
    const tagStr = Constants.tag_to_type(tlv.tag)
    const tagType = Constants.getTagType(tlv.tag)
    switch (tagType) {
        case TagTypes.Universal:
            const parsingFunc = getParsingFunction(tagStr)
            if (parsingFunc === undefined) {
                throw new Error(`No parsing function for ${tagStr} ${tlv.tag.toString(16)}`)
            }
            var parsedResult = parsingFunc(tlv.value)
            return parsedResult
        case TagTypes.Application:
            throw new Error("err")
        case TagTypes.ContextSpecific:
            throw new Error("err")
        case TagTypes.Private:
            throw new Error("err")
    }
}



exports.shiftToLeadingBits = shiftToLeadingBits
exports.getLeadingAndZeroBits = getLeadingAndZeroBits
exports.parseObjectIdentifier = parseObjectIdentifier
exports.parseInteger = parseInteger
exports.parsePrintableString = parsePrintableString
exports.parseIA5String = parseIA5String
exports.parseBoolean = parseBoolean
exports.parseBitString = parseBitString
exports.parseOctetString = parseOctetString
exports.parseUtcTime = parseUtcTime
exports.parseGeneralizedTime = parseGeneralizedTime
exports.parseUtf8String = parseUtf8String
exports.parse = parse