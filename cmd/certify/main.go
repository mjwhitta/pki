package main

import (
	"fmt"
	"strings"

	"github.com/mjwhitta/cli"
	"github.com/mjwhitta/errors"
	hl "github.com/mjwhitta/hilighter"
	"github.com/mjwhitta/log"
	"github.com/mjwhitta/pki"
)

func erase(p *pki.PKI) error {
	var answer string

	fmt.Print(hl.Yellow("Erase PKI (y/N)? "))

	_, _ = fmt.Scanln(&answer)

	switch strings.TrimSpace(strings.ToLower(answer)) {
	case "y", "yes":
		log.Warn("Erasing PKI")

		if e := p.Erase(); e != nil {
			return errors.Newf("failed to erase PKI: %w", e)
		}
	}

	return nil
}

func generateCerts(p *pki.PKI) error {
	var alts []string
	var e error

	if !p.HasCA() {
		log.Info("Creating CA")

		if _, _, e = p.CreateCA(); e != nil {
			return errors.Newf("failed to create CA: %w", e)
		}
	} else {
		log.SubInfo("Using existing CA")
	}

	// Import cert requests, if provided
	for _, csr := range flags.csr {
		log.Infof("Importing cert request %s", csr)

		if e = p.ImportCSR(csr); e != nil {
			return errors.Newf("failed to import CSR: %w", e)
		}
	}

	// Create client certs
	for _, client := range flags.clients {
		alts = strings.Split(client, ":")
		client = alts[0]

		if !p.HasCertFor(client) {
			log.Infof("Creating client cert for %s", client)

			_, _, e = p.CreateCertFor(
				client,
				pki.ClientCert,
				alts[1:]...,
			)
			if e != nil {
				return errors.Newf(
					"failed to create client cert for %s: %w",
					client,
					e,
				)
			}
		} else {
			log.SubInfof("Client %s already has a cert", client)
		}
	}

	// Create server certs
	for _, server := range cli.Args() {
		alts = strings.Split(server, ":")
		server = alts[0]

		if !p.HasCertFor(server) {
			log.Infof("Creating server cert for %s", server)

			_, _, e = p.CreateCertFor(
				server,
				pki.ServerCert,
				alts[1:]...,
			)
			if e != nil {
				return errors.Newf(
					"failed to create server cert for %s: %w",
					server,
					e,
				)
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
				panic(r)
			}

			switch r := r.(type) {
			case error:
				log.ErrX(Exception, r.Error())
			case string:
				log.ErrX(Exception, r)
			}
		}
	}()

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
		fmt.Println(c.String())

		return // Exit to skip sync
	}

	if c, e = pki.CfgFromFile(flags.cfg); e != nil {
		panic(errors.Newf("failed to read PKI config: %w", e))
	}

	if p, e = pki.New(flags.pki, c); e != nil {
		panic(errors.Newf("failed to create PKI: %w", e))
	}

	if flags.erase {
		if e = erase(p); e != nil {
			panic(e)
		}

		return // Exit to skip sync
	}

	// All below options will Sync after
	switch {
	case flags.undo:
		e = undo(p)
	case flags.revoke:
		e = revokeCerts(p)
	default:
		e = generateCerts(p)
	}

	if e != nil {
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
				return errors.Newf(
					"failed to revoke cert for %s: %w",
					cn,
					e,
				)
			}
		} else {
			log.Warnf("No cert found for %s", cn)
		}
	}

	return nil
}

func undo(p *pki.PKI) error {
	log.Warn("Rolling back PKI")

	if e := p.Undo(); e != nil {
		return errors.Newf("failed to rollback PKI: %w", e)
	}

	return nil
}
