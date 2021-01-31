
function bytesToHex(bytes) {
    var hex = []
    bytes.forEach(b => hex.push(("0" + b.toString(16)).slice(-2)))
    hex = hex.join(":")
    return hex
}


exports.bytesToHex = bytesToHex