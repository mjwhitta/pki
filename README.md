# PKI

[![Yum](https://img.shields.io/badge/-Buy%20me%20a%20cookie-blue?labelColor=grey&logo=cookiecutter&style=for-the-badge)](https://www.buymeacoffee.com/mjwhitta)

[![Go Report Card](https://goreportcard.com/badge/github.com/mjwhitta/pki?style=for-the-badge)](https://goreportcard.com/report/github.com/mjwhitta/pki)
[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/mjwhitta/pki/ci.yaml?style=for-the-badge)](https://github.com/mjwhitta/pki/actions)
![License](https://img.shields.io/github/license/mjwhitta/pki?style=for-the-badge)

## What is this?

A tool to ease the headache of PKI infrastructure generation.

## How to install

Open a terminal and run the following:

```
$ go get -u github.com/mjwhitta/pki
$ go install github.com/mjwhitta/pki/cmd/certify@latest
```

Or compile from source:

```
$ git clone https://github.com/mjwhitta/pki.git
$ cd pki
$ git submodule update --init
$ make
```

## Usage

**Note:** Regardless of how you use this Go tool, you should be aware
that the certificates on disk are used as a database. Moving or
removing files can lead to unintended side-effects (failure to revoke,
etc...). You have been warned.

### CLI

To get started with a simple PKI:

```
$ mkdir -p .../path/to/pki
$ certify --sample >.../path/to/pki/.cfg
$ # Modify .cfg as needed
$ certify --pki .../path/to/pki
```

You now have a PKI with a self-signed CA ready to go. If you would
like to use your own CA (maybe an intermediate CA signed by a Trusted
Root CA), now is the time to overwrite `ca/ca.cert.pem` and
`private/ca.key.pem` in the PKI directory. You can delete or overwrite
the DER files as well. See `certify --help` for what to do next.

```
$ # Create server certificate
$ certify --pki .../path/to/pki test.example.com
$ # Create wildcard certificate
$ certify --pki .../path/to/pki "example.com:*.example.com"
```

### Library

```
package main

import "github.com/mjwhitta/pki"

func main() {
    var e error
    var p *pki.PKI

    // Create PKI structure
    if p, e = pki.New(".../path/to/pki", pki.NewCfg()); e != nil {
        panic(e)
    }

    // Create CA
    if _, _, e = p.CreateCA(); e != nil {
        panic(e)
    }

    // Create server Certificate
    _, _, e = p.CreateCertFor("test.example.com", pki.ServerCert)
    if e != nil {
        panic(e)
    }

    // Create wildcard Certificate
    _, _, e = p.CreateCertFor(
        "example.com",
        pki.ServerCert,
        "*.example.com",
    )
    if e != nil {
        panic(e)
    }

    // Sync the ders and pems directories for convenience
    if e = p.Sync(); e != nil {
        panic(e)
    }
}
```

## Links

- [Source](https://github.com/mjwhitta/pki)

## TODO

- Consider support for intermediary CAs
