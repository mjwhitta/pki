package main

import (
	"os"
	"path/filepath"
	"strings"

	"gitlab.com/mjwhitta/cli"
	hl "gitlab.com/mjwhitta/hilighter"
	"gitlab.com/mjwhitta/pathname"
	"gitlab.com/mjwhitta/pki"
)

// Exit status
const (
	Good = iota
	InvalidOption
	MissingOption
	InvalidArgument
	MissingArgument
	ExtraArgument
	Exception
)

// Flags
var flags struct {
	clients cli.StringList
	cfg     string
	csr     cli.StringList
	erase   bool
	nocolor bool
	pki     string
	revoke  bool
	sample  bool
	undo    bool
	verbose bool
	version bool
}

func init() {
	// Configure cli package
	cli.Align = true
	cli.Authors = []string{"Miles Whittaker <mj@whitta.dev>"}
	cli.Banner = hl.Sprintf(
		"%s [OPTIONS] [host1]...[hostN]",
		os.Args[0],
	)
	cli.BugEmail = "pki.bugs@whitta.dev"
	cli.ExitStatus = strings.Join(
		[]string{
			"Normally the exit status is 0. In the event of an error",
			"the exit status will be one of the below:\n\n",
			hl.Sprintf("%d: Invalid option\n", InvalidOption),
			hl.Sprintf("%d: Missing option\n", MissingOption),
			hl.Sprintf("%d: Invalid argument\n", InvalidArgument),
			hl.Sprintf("%d: Missing argument\n", MissingArgument),
			hl.Sprintf("%d: Extra argument\n", ExtraArgument),
			hl.Sprintf("%d: Exception", Exception),
		},
		" ",
	)
	cli.Info = strings.Join(
		[]string{
			"Easily generate a self-signed CA and issue",
			"client/server certificates.",
		},
		" ",
	)
	cli.SeeAlso = []string{"openssl"}

	// Parse cli flags
	cli.Flag(
		&flags.clients,
		"c",
		"client",
		"Create client certificate (can be used more than once).",
	)
	cli.Flag(
		&flags.cfg,
		"cfg",
		"",
		"Use specified config (default: <pki>/.cfg).",
	)
	cli.Flag(
		&flags.csr,
		"csr",
		"",
		"Import cert request first (can be used more than once).",
	)
	cli.Flag(
		&flags.erase,
		"e",
		"erase",
		false,
		"Erase PKI files and subdirectories.",
	)
	cli.Flag(
		&flags.nocolor,
		"no-color",
		false,
		"Disable colorized output.",
	)
	cli.Flag(
		&flags.pki,
		"p",
		"pki",
		"./",
		"Use specified directory for PKI (default: ./).",
	)
	cli.Flag(
		&flags.revoke,
		"r",
		"revoke",
		false,
		"Revoke specified certificates, rather than create.",
	)
	cli.Flag(
		&flags.sample,
		"s",
		"sample",
		false,
		"Generate sample config.",
	)
	cli.Flag(
		&flags.undo,
		"u",
		"undo",
		false,
		"Rollback most recent generated certificate.",
	)
	cli.Flag(
		&flags.verbose,
		"v",
		"verbose",
		false,
		"Show stacktrace, if error.",
	)
	cli.Flag(&flags.version, "V", "version", false, "Show version.")
	cli.Parse()
}

// Process cli flags and ensure no issues
func validate() {
	hl.Disable(flags.nocolor)

	// Normalized cfg
	if flags.cfg == "" {
		// Backwards compatibility
		flags.cfg = filepath.Join(flags.pki, "certifyme.conf")
		if ok, _ := pathname.DoesExist(flags.cfg); !ok {
			// New default config going forward
			flags.cfg = filepath.Join(flags.pki, ".cfg")
		}
	}

	// Undo must be used alone
	if flags.undo {
		if (len(flags.csr) > 0) || flags.revoke {
			cli.Usage(InvalidOption)
		} else if (len(flags.clients) + cli.NArg()) > 0 {
			cli.Usage(ExtraArgument)
		}
	}

	// CSR and revoke can not be used together
	if (len(flags.csr) > 0) && flags.revoke {
		cli.Usage(InvalidOption)
	}

	// Short circuit if version was requested
	if flags.version {
		hl.Printf("certifyme version %s\n", pki.Version)
		os.Exit(Good)
	}
}
