package main

import (
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/grantae/certinfo"
	"io/ioutil"
	"log"
	"os"
)

var opt_out string

// main parses one or more files provided on the command
// line and prints the certificates in the specified format
// (the default being "info").
func main() {
	flag.StringVar(&opt_out, "o", "info", "output type: info, pem, or der")

	flag.Parse()

	args := flag.Args()

	for i := 0; i < len(args); i++ {
		buf, err := ioutil.ReadFile(args[i])
		if err != nil {
			log.Printf("unable to open file %s: %v", args[i], err)
			continue
		}

		/* 1st, try DER encoding */
		crt, err := x509.ParseCertificates(buf)
		if err == nil && len(crt) > 0 {
			for i := 0; i < len(crt); i++ {
				outputCert(crt[i], opt_out)
			}
		} else { /* 2nd, try PEM encoding */
			for {
				block, remaining := pem.Decode(buf)
				if block != nil {
					crt, err := x509.ParseCertificate(block.Bytes)
					if err == nil {
						outputCert(crt, opt_out)
					}
				}
				if buf = remaining; len(buf) == 0 {
					break
				}
			}
		}
	}
}

// outputCert prints a certificate to STDOUT using the
// specified formats, "info", "pem", or binary "der".
func outputCert(crt *x509.Certificate, out string) {
	switch out {
	case "info":
		txt, err := certinfo.CertificateText(crt)
		if err == nil {
			fmt.Println(txt)
		} else {
			log.Printf("unable to extract certificate details: %v", err)
		}
	case "pem":
		pem.Encode(os.Stdout, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: crt.Raw})
	case "der":
		os.Stdout.Write(crt.Raw)
	default:
		log.Println("unrecognized -t option (valid values are: info, pem, and der):", out)
		os.Exit(1)
	}
}
