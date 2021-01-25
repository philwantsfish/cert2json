const Constants = require('./constants')
const TagTypes = Constants.TagTypes
const DER = require('./der-parse')


// NOTES
// This file contains the necessary functions to convert a binary certificate file (DER) into a set of TVL tokens. 

function get_len(data, offset) {
    const leadingByte = data.readInt8(offset)
    const lenHasMultipleBytes = (leadingByte & 0x80) === 0x80
    if (lenHasMultipleBytes) {
        const numBytes = leadingByte & 0x7F
        var len
        switch (numBytes) {
            case 1:
                len = data.readUInt8(offset + 1)
                break;
            case 2:
                len = data.readUInt16BE(offset + 1)
                break;
            case 4:
                len = data.readUInt32BE(offset + 1)
                break;
            default: 
                throw new Error(`Expected numBytes to be one of [1, 2, 4], but got ${numBytes}`)
        }
        return [numBytes + 1, len]
    } else {
        return [1, leadingByte]
    }
}

function isTagAList(tag) {
    return (
        tag === Constants.UniversalTags.SEQUENCE ||
        tag === Constants.UniversalTags.SET ||
        Constants.getTagType(tag) === Constants.TagTypes.ContextSpecific    
    ) 
}

function get_tlv_universal(data, offset) {
    // Get the tag byte
    const tag = data.readUInt8(offset)

    // Calculate the length of the length and the length of tlv
    const [lenOfLen, lenOfValue] = get_len(data, offset + 1)
    const lenOfTlv = 1 + lenOfLen + lenOfValue

    // Get the raw bytes of the value
    const valueStart = offset + 1 + lenOfLen
    const value = data.slice(valueStart, valueStart + lenOfValue) 

    const tagStr = Constants.tag_to_type(tag)

    var tlv = {
        tag: tag,
        tagStr: tagStr,
        len: lenOfValue,
        value: value,
        lenOfTlv: lenOfTlv,
        lenOfLen: lenOfLen,
        offset: offset
    }
    
    // Parse the value bytes and return the tlv
    if (isTagAList(tag)) {
        // Recurse 
        const tlvs = []

        var subOffset = 0
        while(true) {
            const tlv = get_tlv(value, subOffset)
            if (tlv !== undefined) {
                tlvs.push(tlv)
                subOffset = subOffset + tlv.lenOfTlv
            } else {
                break
            }
        }
        tlv.parsedResult = tlvs
        return tlv   
    } else {
        const parsedResult = DER.parse(tlv)
        tlv.parsedResult = parsedResult
        return tlv   
    }
}

function get_tlv_contextspecific(data, offset) {
    const tag = data.readUInt8(offset)
    const [lenOfLen, lenOfValue] = get_len(data, offset + 1)
    const lenOfTlv = 1 + lenOfLen + lenOfValue

    const valueStart = offset + 1 + lenOfLen
    const value = data.slice(valueStart, valueStart + lenOfValue)
    const tagStr = Constants.tag_to_type(tag)

    const tlv = {
        tag: tag,
        tagStr: tagStr,
        len: lenOfValue,
        value: value,
        lenOfTlv: lenOfTlv,
        lenOfLen: lenOfLen,
        offset: offset
    }

    const tlvs = []
    var subOffset = 0
    while(true) {
        const tlv = get_tlv(value, subOffset)
        if (tlv !== undefined) {
            tlvs.push(tlv)
            subOffset = subOffset + tlv.lenOfTlv
        } else {
            break
        }
    }
    tlv.parsedResult = tlvs

    return tlv
}


// This function returns a tlv and the next offset to continue parsing
function get_tlv(data, offset) {
    if (offset >= data.length) {
        return undefined
    }

    // The tag type is defined by the two highest bits
    const tagByte = data.readUInt8(offset)
    const tagType = Constants.getTagType(tagByte)

    switch (tagType) {
        case TagTypes.Universal:
            return get_tlv_universal(data, offset)
        case TagTypes.Application:
            throw new Error("err")
        case TagTypes.ContextSpecific:
            return get_tlv_contextspecific(data, offset)
        case TagTypes.Private:
            throw new Error("err")
        default:
            throw new Error(`Impressive you hit an impossible condition. Two leading bits: ${twoLeadingBits}`)
    }
}

// Converts binary data into TLV tokens
function tokenize(data) {
    var tlvs = []
    var offset = 0
    while (offset < data.length) {
        const tlv = get_tlv(data, offset)
        tlvs.push(tlv)
        offset = offset + tlv.lenOfTlv
    }

    return tlvs
}


function parse(data) {
    function recurse(tlv) {
        const parsedResult = tlv.parsedResult
        if (Array.isArray(parsedResult)) {
            const arr = []
            parsedResult.forEach(r => {
                const item = recurse(r)
                arr.push(item)
            })
            return arr
        } else {
            // Not an array, stop recursing
            return parsedResult
        }
    }
    const tlvs = tokenize(data)
    if (tlvs.length > 1) {
        throw new Error("Root node has more than one TLV")
    }
    return recurse(tlvs[0])
}

exports.tokenize = tokenize
exports.parse = parse