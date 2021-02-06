#!/usr/bin/env node
const parser = require('./certificate')
const path = require('path');
const fs = require('fs');

function print_help() {
    const help = `usage: cert2json file`
    console.log(help)
}

function print_version() {
    var pjson = require('../package.json');
    console.log(`Version ${pjson.version}`);
}

function isPem(data) {
    return data.includes("BEGIN CERTIFICATE")
}

const arguments = process.argv.slice(2)

if (arguments.length !== 1 || arguments.includes('-h') || arguments.includes('--help')) {
    print_help()
    return
}

if (arguments.includes('-v') || arguments.includes('--version')) {
    print_version()
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
    const certificate = parser.parse(data)
    console.log(JSON.stringify(certificate, null, 2))
}
