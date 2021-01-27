#!/usr/bin/env node
const parser = require('./certificate')
const path = require('path');
const fs = require('fs');

function print_help() {
    const help = `usage: cert2json file`
    console.log(help)
}

function isPem(data) {
    return data.includes("BEGIN CERTIFICATE")
}

const arguments = process.argv.slice(2)

if (arguments.length !== 1) {
    print_help()
    return
}

const resolvedPath = `${path.resolve(arguments[0])}`
const data = fs.readFileSync(resolvedPath)

if (isPem(data)) {
    // Remove the BEGIN CERTIFICATE and END CERTIFICATE lines
    const b64 = data.toString().replace(/(-----(BEGIN|END) CERTIFICATE-----|[\n\r])/g, '')
    // The remaining data is base64 encoded
    const buf = Buffer.from(b64, 'base64')
    const certificate = parser.parse(buf)
    console.log(JSON.stringify(certificate, null, 2))
} else {
    console.log(`[+] Assuming certificate is der format`)
    const certificate = parser.parse(data)
    console.log(JSON.stringify(certificate, null, 2))
}
