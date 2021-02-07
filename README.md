<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Thanks again! Now go create something AMAZING! :D
***
***
***
*** To avoid retyping too much info. Do a search and replace for the following:
*** twitter_handle, email, project_title, project_description
-->



<!-- PROJECT LOGO -->
<p align="center">
  <h3 align="center">cert2json</h3>

  <p align="center">
    Convert a x509 certificate to JSON format
    <br />
    <a href="https://github.com/philwantsfish/cert2json">View Demo</a>
    ·
    <a href="https://github.com/philwantsfish/cert2json/issues">Report Bug</a>
    ·
    <a href="https://github.com/philwantsfish/cert2json/issues">Request Feature</a>
  </p>
</p>



<!-- TABLE OF CONTENTS -->
<details open="open">
  <summary><h2 style="display: inline-block">Table of Contents</h2></summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#install-cli">Install CLI</a></li>
        <li><a href="#install-api">Install API</a></li>
      </ul>
    </li>
    <li>
        <a href="#usage">Usage</a>
        <ul>
            <li><a href="#cli-example">CLI Example</a></li>
            <li><a href="#api-examples">API Examples</a></li>
        </ul>
    </li>
    <li><a href="#contributing">Contributing</a></li>
    <li><a href="#license">License</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

This project converts x509 certificates into JSON format. It provides both a command line interface and an API. 


<!-- GETTING STARTED -->
## Getting Started

To get a local copy up and running follow these simple steps.

### Install CLI

Run the following command to install the CLI

```sh
npm install -g cert2json
```


### Install API

In your npm package install the dependency

```sh
npm install cert2json
```

## Usage

<!-- USAGE EXAMPLES -->
### CLI Example

The CLI will print the JSON. You can use [jq](https://github.com/stedolan/jq) to process the output. Below is an example printing the certificate issuer.

```sh
➜  cert2json -h
usage: cert2json file
➜  cert2json google.com.cer | jq '.tbs.issuer.full'
"C=US, O=Google Trust Services, CN=GTS CA 1O1"
➜  
```

### API Examples

Import cert2json and call parseFromFile. The certificate can be DER or PEM format. 

```javascript
// Import the library
const cert2json = require('cert2json')

// Parse the certificate, resulting in a JSON object
const cert = cert2json.parseFromFile('./certificates/google.com.cer')

// Print the issuer
console.log(cert.tbs.issuer.full)
```

Results in:

```
C=US, O=Google Trust Services, CN=GTS CA 1O1
```

Alternatively you can parse the certificate from memory. The parse function expects a [Buffer](https://nodejs.org/api/buffer.html) containing the certificate data.

```javascript
// Import the library
const cert2json = require('cert2json')
const fs = require('fs')

// Read the certificate into a buffer
const certificatePath = './certificates/example.com.cer'
const certificateBuffer = fs.readFileSync(certificatePath)

// Parse the buffer contents
const cert = cert2json.parse(certificateBuffer)

// Print the certificate
console.log(JSON.stringify(cert, null, 2))
```

<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to be learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE` for more information.

