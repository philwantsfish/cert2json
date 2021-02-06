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
        <li><a href="#installation">CLI Installation</a></li>
        <li><a href="#installation">API Installation</a></li>
      </ul>
    </li>
    <li>
        <a href="#usage">Usage</a>
        <ul>
            <li><a href="#installation">CLI Example</a></li>
            <li><a href="#installation">API Example</a></li>
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


<!-- USAGE EXAMPLES -->
## Usage CLI

The CLI will print the JSON. You can use [jq](https://github.com/stedolan/jq) to process the output. Below is an example printing the certificate issuer.

```sh
➜  cert2json -h
usage: cert2json file
➜  cert2json google.com.cer | jq '.tbs.issuer.full'
"C=US, O=Google Trust Services, CN=GTS CA 1O1"
➜  
```

## Usage API

Import the library

```javascript
const cert2json = require('cert2json');
```

Read the certificate file

```javascript
const path = require('path');
const GoogleCertificatePath = `${path.resolve('./google.com.cer')}`
const fs = require('fs');
const GoogleCertificateData = fs.readFileSync(GoogleCertificatePath)
```

Parse the certificate, resulting in the same JSON object as above

```javascript
const cert = cert2json.parse(GoogleCertificateData)
```

Print the certificate to stdout

```javascript
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

