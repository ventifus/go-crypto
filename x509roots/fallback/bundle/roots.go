package bundle

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	_ "embed"
)

//go:embed bundle.der
var rawCerts []byte

type Root struct {
	Certificate []byte                          // DER-encoded certificate
	Constraint  func([]*x509.Certificate) error // nil if root is unconstrained
}

// Roots returns the parsed bundle of roots from the NSS trust store. Constrained roots will have a non-nil
// Root.Constraint function. All other roots are unconstrained.
func Roots() []Root {
	var roots []Root
	for _, c := range mustParse(unparsedCertificates) {
		roots = append(roots, Root{
			Certificate: c.cert,
			Constraint:  c.constraint,
		})
	}
	return roots
}

type unparsedCertificate struct {
	cn         string
	sha256Hash string
	pem        string

	// possible constraints
	distrustAfter string
}

type parsedCertificate struct {
	cert        *x509.Certificate
	constraints []func([]*x509.Certificate) error
}

func mustParse(unparsedCerts []unparsedCertificate) []parsedCertificate {
	var b []parsedCertificate
	for _, unparsed := range unparsedCerts {
		block, rest := pem.Decode([]byte(unparsed.pem))
		if block == nil {
			panic(fmt.Sprintf("unexpected nil PEM block for %q", unparsed.cn))
		}
		if len(rest) != 0 {
			panic(fmt.Sprintf("unexpected trailing data in PEM for %q", unparsed.cn))
		}
		if block.Type != "CERTIFICATE" {
			panic(fmt.Sprintf("unexpected PEM block type for %q: %s", unparsed.cn, block.Type))
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			panic(err)
		}
		parsed := parsedCertificate{cert: cert}
		// parse possible constraints, this should check all fields of unparsedCertificate.
		if unparsed.distrustAfter != "" {
			distrustAfter, err := time.Parse(time.RFC3339, unparsed.distrustAfter)
			if err != nil {
				panic(fmt.Sprintf("failed to parse distrustAfter %q: %s", unparsed.distrustAfter, err))
			}
			parsed.constraints = append(parsed.constraints, func(chain []*x509.Certificate) error {
				for _, c := range chain {
					if c.NotBefore.After(distrustAfter) {
						return fmt.Errorf("certificate issued after distrust-after date %q", distrustAfter)
					}
				}
				return nil
			})
		}
		b = append(b, parsed)
	}
	return b
}
