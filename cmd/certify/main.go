package main

import (
	"fmt"
	"os"
	"strings"

	"gitlab.com/mjwhitta/cli"
	"gitlab.com/mjwhitta/errors"
	hl "gitlab.com/mjwhitta/hilighter"
	"gitlab.com/mjwhitta/log"
	"gitlab.com/mjwhitta/pki"
)

func generateCerts(p *pki.PKI) error {
	var e error

	if !p.HasCA() {
		log.Info("Creating CA")
		if _, _, e = p.CreateCA(); e != nil {
			return e
		}
	} else {
		log.SubInfo("Using existing CA")
	}

	// Import cert requests, if provided
	for _, csr := range flags.csr {
		log.Infof("Importing cert request %s", csr)
		if e = p.ImportCSR(csr); e != nil {
			return e
		}
	}

	// Create client certs
	for _, client := range flags.clients {
		if !p.HasCertFor(client) {
			log.Infof("Creating client cert for %s", client)
			_, _, e = p.CreateCertFor(client, pki.ClientCert)
			if e != nil {
				return e
			}
		} else {
			log.SubInfof("Client %s already has a cert", client)
		}
	}

	// Create server certs
	for _, server := range cli.Args() {
		if !p.HasCertFor(server) {
			log.Infof("Creating server cert for %s", server)
			_, _, e = p.CreateCertFor(server, pki.ServerCert)
			if e != nil {
				return e
			}
		} else {
			log.SubInfof("Server %s already has a cert", server)
		}
	}

	return nil
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			if flags.verbose {
				panic(r.(error).Error())
			}
			log.ErrX(Exception, r.(error).Error())
		}
	}()

	var ans string
	var c *pki.Cfg
	var e error
	var p *pki.PKI

	validate()

	if flags.sample {
		c = pki.NewCfg()
		c.CommonName("Self-signed CA")
		c.City("City name")
		c.Company("Company name")
		c.Country("US")
		c.State("State name")
		c.Unit("Department")
		hl.Println(c.String())
		os.Exit(Good)
	}

	if c, e = pki.CfgFromFile(flags.cfg); e != nil {
		panic(errors.Newf("failed to read PKI config: %w", e))
	}

	if p, e = pki.New(flags.pki, c); e != nil {
		panic(errors.Newf("failed to create PKI: %w", e))
	}

	if flags.erase {
		hl.PrintYellow("Erase PKI (y/N)? ")
		fmt.Scanln(&ans)

		switch strings.TrimSpace(strings.ToLower(ans)) {
		case "y", "yes":
			log.Warn("Erasing PKI")
			if e = p.Erase(); e != nil {
				panic(errors.Newf("failed to erase PKI: %w", e))
			}
		}

		os.Exit(Good) // Exit so as not to sync
	}

	// All below options will Sync after
	if flags.undo {
		log.Warn("Rolling back PKI")
		if e = p.Undo(); e != nil {
			panic(errors.Newf("failed to rollback PKI: %w", e))
		}
	} else if flags.revoke {
		if e = revokeCerts(p); e != nil {
			panic(e)
		}
	} else if e = generateCerts(p); e != nil {
		panic(e)
	}

	if e = p.Sync(); e != nil {
		panic(e)
	}
}

func revokeCerts(p *pki.PKI) error {
	var e error

	if !p.HasCA() {
		// Nothing to revoke yet
		return errors.New("no CA created yet")
	}

	// Revoke client and server certs
	for _, cn := range append(flags.clients, cli.Args()...) {
		if p.HasCertFor(cn) {
			log.Warnf("Revoking cert for %s", cn)
			if _, e = p.RevokeCertFor(cn); e != nil {
				return e
			}
		} else {
			log.Warnf("No cert found for %s", cn)
		}
	}

	return nil
}
