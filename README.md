# PKI

<a href="https://www.buymeacoffee.com/mjwhitta">🍪 Buy me a cookie</a>

[![Go Report Card](https://goreportcard.com/badge/gitlab.com/mjwhitta/pki)](https://goreportcard.com/report/gitlab.com/mjwhitta/pki)
[![Pipeline](https://gitlab.com/mjwhitta/pki/badges/master/pipeline.svg)](https://gitlab.com/mjwhitta/pki/-/pipelines/latest)
[![Coverage](https://gitlab.com/mjwhitta/pki/badges/master/coverage.svg)](https://gitlab.com/mjwhitta/pki)

## What is this?

A tool to ease the headache of PKI infrastructure generation.

## How to install

Open a terminal and run the following:

```
$ # For library usage
$ go get --ldflags "-s -w" --trimpath -u gitlab.com/mjwhitta/pki
$ # For cli usage
$ go install --ldflags "-s -w" --trimpath \
    gitlab.com/mjwhitta/pki/cmd/certify@latest
```

Or compile from source:

```
$ git clone https://gitlab.com/mjwhitta/pki.git
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

### Library

```
package main

import (
    "crypto/rsa"
    "crypto/x509"

    "gitlab.com/mjwhitta/pki"
)

func main() {
    var c *x509.Certificate
    var ca *x509.Certificate
    var e error
    var k *rsa.PrivateKey
    var p *pki.PKI

    // Create PKI structure
    if p, e = pki.New("/pki/root/dir", pki.NewCfg()); e != nil {
        panic(e)
    }

    // Create CA
    if ca, k, e = p.CreateCA(); e != nil {
        panic(e)
    }

    // Do stuff with your CA
    println(ca.Subject.CommonName)
    println(k.PublicKey.Size())

    // Create server Certificate
    c, k, e = p.CreateCertFor("example.com", pki.ServerCert)
    if e != nil {
        panic(e)
    }

    // Do stuff with your new Certificate
    println(c.Subject.CommonName)
    println(k.PublicKey.Size())

    // Sync the ders and pems directories for convenience
    if e = p.Sync(); e != nil {
        panic(e)
    }
}
```

## Links

- [Source](https://gitlab.com/mjwhitta/pki)

## TODO

- Consider support for intermediary CAs
