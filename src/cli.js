#!/usr/bin/env node
const parser = require('./certificate')
const path = require('path');
const fs = require('fs');


// Should handle pem as well 
// See example here: https://gist.github.com/adisbladis/c84e533e591b1737fedd26658021fef2


const arguments = process.argv.slice(2)

if (arguments.length !== 1) {
    console.log(`Provide a single argument that is a file path`)
}

const resolvedPath = `${path.resolve(arguments[0])}`
const data = fs.readFileSync(resolvedPath)
const certificate = parser.parse(data)


console.log(JSON.stringify(certificate, null, 2))