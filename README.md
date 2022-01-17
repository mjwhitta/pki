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
$ go get --ldflags "-s -w" --trimpath -u gitlab.com/mjwhitta/pki
$ go install --ldflags "-s -w" --trimpath \
    gitlab.com/mjwhitta/pki/cmd/certify@latest
```

Or install from source:

```
$ git clone https://gitlab.com/mjwhitta/pki.git
$ cd pki
$ git submodule update --init
$ make
```

## Usage

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
}
```

## Links

- [Source](https://gitlab.com/mjwhitta/pki)

## TODO

- Consider support for intermediary CAs
