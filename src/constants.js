
const TagTypes = Object.freeze({
    Universal: 0x00,       // 0000
    Application: 0x010,    // 0100
    ContextSpecific: 0x80, // 1000
    Private: 0xC0          // 1100
  })

function getTagType(byte) {
    const twoLeadingBits = (byte & 0xC0)
    switch (twoLeadingBits) {
        case TagTypes.Universal:
            return TagTypes.Universal
        case TagTypes.Application:
            return TagTypes.Application
        case TagTypes.ContextSpecific:
            return TagTypes.ContextSpecific
        case TagTypes.Private:
            return TagTypes.Private
        default:
            throw new Error(`Impressive you hit an impossible condition. Two leading bits: ${twoLeadingBits}`)
    }
}

const UniversalTags = Object.freeze({
    BOOLEAN: 0x01,
    INTEGER: 0x02,
    BITSTRING: 0x03,
    OCTETSTRING: 0x04,
    NULL: 0x05,
    OBJECT: 0x06,
    UTF8STRING: 0x0C,
    UTCTIME: 0x17,
    PRINTABLESTRING: 0x13,
    SEQUENCE: 0x30,
    SET: 0x31
})

function tag_to_type(tag) {
    const ContextSpecific = 0xA0
    if ((tag & 0xF0) === ContextSpecific) {
        const n = (tag & 0x0F)
        return `cont [ ${n} ]`
    }

    switch(tag) {
        case 0x01:
            return "BOOLEAN"
        case 0x02:
            return "INTEGER"
        case 0x03:
            return "BITSTRING"
        case 0x04:
            return "OCTETSTRING"
        case 0x05:
            return "NULL"
        case 0x06:
            return "OBJECT"
        case 0x0C:
            return "UTF8STRING"
        // case 0x12:
        case 0x17:
            return "UTCTIME"
        case 0x13:
            return "PRINTABLESTRING"
        case 0x30:
            return "SEQUENCE"
        case 0x31:
            return "SET"
        default:
            return `UNKNOWN (${tag.toString(16)})`
    }
}

exports.TagTypes = TagTypes
exports.UniversalTags = UniversalTags
exports.getTagType = getTagType
exports.tag_to_type = tag_to_type