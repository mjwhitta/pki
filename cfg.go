package pki

import (
	"crypto/x509/pkix"
	"os"
	"strconv"
	"strings"

	"github.com/mjwhitta/errors"
	"github.com/mjwhitta/pathname"
)

// Cfg contains any relevant configuration options for creating PKI
// infrastructure.
type Cfg struct {
	CADaysValid   int
	CertDaysValid int

	subject map[string]string
}

// CfgFromFile will parse the specified file and create a new Cfg
// instance.
func CfgFromFile(fn string) (*Cfg, error) {
	var b []byte
	var cfg *Cfg
	var e error

	if e = ensureExists("file", fn); e != nil {
		return nil, e
	}

	cfg = NewCfg()

	if b, e = os.ReadFile(pathname.ExpandPath(fn)); e != nil {
		return nil, errors.Newf("failed to read %s", fn)
	}

	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)

		// Ignore comments and empty lines
		if (line == "") || strings.HasPrefix(line, "#") {
			continue
		}

		// Split option on =
		if k, v, ok := strings.Cut(line, "="); ok {
			// Strip whitespace
			k = strings.ToLower(strings.TrimSpace(k))
			v = strings.TrimSpace(v)

			// Strip leading and trailing ", if coming from bash
			// CertifyMe
			v = strings.TrimPrefix(v, "\"")
			v = strings.TrimSuffix(v, "\"")

			if e = cfg.SetOption(k, v); e != nil {
				return nil, e
			}

			continue
		}

		return nil, errors.Newf("invalid config syntax: %s", line)
	}

	return cfg, nil
}

// NewCfg will create a new default instance of Cfg.
func NewCfg() *Cfg {
	return &Cfg{
		CADaysValid:   365, //nolint:mnd // 1 year
		CertDaysValid: 365, //nolint:mnd // 1 year
		subject:       map[string]string{"CN": "Self-signed CA"},
	}
}

// City is an alias for Locality().
func (cfg *Cfg) City(c string) {
	cfg.Locality(c)
}

// CommonName will set the CN in the certificate's subject.
func (cfg *Cfg) CommonName(cn string) {
	if cn == "" {
		cn = "Self-signed CA"
	}

	cfg.subject["CN"] = cn
}

// Company is an alias for Organization().
func (cfg *Cfg) Company(c string) {
	cfg.Organization(c)
}

// Country will set the C in the certificate's subject.
func (cfg *Cfg) Country(c string) {
	cfg.subject["C"] = c
}

// Locality will set the L in the certificate's subject.
func (cfg *Cfg) Locality(l string) {
	cfg.subject["L"] = l
}

// Organization will set the O in the certificate's subject.
func (cfg *Cfg) Organization(o string) {
	cfg.subject["O"] = o
}

// OrganizationalUnit will set the OU in the certificate's subject.
func (cfg *Cfg) OrganizationalUnit(ou string) {
	cfg.subject["OU"] = ou
}

// Province will set the ST in the certificate's subject.
func (cfg *Cfg) Province(p string) {
	cfg.subject["ST"] = p
}

// SetOption will allow you to set supported configuration options.
func (cfg *Cfg) SetOption(k, v string) error {
	var e error

	switch k {
	case "cacn", "cn":
		cfg.CommonName(v)
	case "cadays":
		if cfg.CADaysValid, e = strconv.Atoi(v); e != nil {
			return errors.Newf("invalid value for %s: %s", k, v)
		}
	case "capass":
		// This is ignored but left for backwards compatibility
	case "certdays":
		if cfg.CertDaysValid, e = strconv.Atoi(v); e != nil {
			return errors.Newf("invalid value for %s: %s", k, v)
		}
	case "city", "l", "locality":
		cfg.City(v)
	case "company", "o", "org", "organization":
		cfg.Company(v)
	case "c", "country":
		cfg.Country(v)
	case "create_der":
		// This is ignored but left for backwards compatibility
	case "province", "st", "state":
		cfg.State(v)
	case "department", "ou", "unit":
		cfg.Unit(v)
	default:
		return errors.Newf("invalid config option %s", k)
	}

	return nil
}

// State is an alias for Province().
func (cfg *Cfg) State(s string) {
	cfg.Province(s)
}

// String will return a string representation of the Cfg.
func (cfg *Cfg) String() string {
	var out []string = []string{
		"# Adjust and uncomment these values as needed",
		"",
		"cacn = " + cfg.subject["CN"],
	}

	if cfg.CADaysValid == 365 { //nolint:mnd // 1 year
		out = append(out, "#cadays = 365")
	} else {
		out = append(out, "cadays = "+strconv.Itoa(cfg.CADaysValid))
	}

	if cfg.CertDaysValid == 365 { //nolint:mnd // 1 year
		out = append(out, "#certdays = 365")
	} else {
		out = append(
			out,
			"certdays = "+strconv.Itoa(cfg.CertDaysValid),
		)
	}

	if cfg.subject["L"] != "" {
		out = append(out, "city = "+cfg.subject["L"])
	}

	if cfg.subject["O"] != "" {
		out = append(out, "company = "+cfg.subject["O"])
	}

	if cfg.subject["C"] != "" {
		out = append(out, "country = "+cfg.subject["C"])
	}

	if cfg.subject["ST"] != "" {
		out = append(out, "state = "+cfg.subject["ST"])
	}

	if cfg.subject["OU"] != "" {
		out = append(out, "unit = "+cfg.subject["OU"])
	}

	return strings.Join(out, "\n")
}

// Subject will return the constructed Subject.
func (cfg *Cfg) Subject(cn ...string) pkix.Name {
	var name pkix.Name

	if len(cn) == 0 {
		cn = append(cn, cfg.subject["CN"])
	}

	name = pkix.Name{CommonName: cn[0]}

	if cfg.subject["C"] != "" {
		name.Country = []string{cfg.subject["C"]}
	}

	if cfg.subject["L"] != "" {
		name.Locality = []string{cfg.subject["L"]}
	}

	if cfg.subject["O"] != "" {
		name.Organization = []string{cfg.subject["O"]}
	}

	if cfg.subject["OU"] != "" {
		name.OrganizationalUnit = []string{cfg.subject["OU"]}
	}

	if cfg.subject["ST"] != "" {
		name.Province = []string{cfg.subject["ST"]}
	}

	return name
}

// Unit is an alias for OrganizationalUnit().
func (cfg *Cfg) Unit(u string) {
	cfg.OrganizationalUnit(u)
}
