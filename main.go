package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"github.com/grantae/certinfo"
	"io/ioutil"
	"log"
	"net"
	"net/url"
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
		v := args[i]

		// attempt to read v as a local file, if that fails
		// fallback to checking for urls or host:port
		// addresses
		buf, err := ioutil.ReadFile(v)
		if err != nil {

			var host string
			var port string

			if u, err := url.Parse(v); u != nil {
				host, port, err = net.SplitHostPort(u.Host)
				if err != nil {
					if u.Scheme == "https" && u.Host != "" {
						host, port = u.Host, "443"
					} else {
						log.Printf("unable to open file, url, or address %s: %v", v, err)
						continue
					}
				}
			} else {
				host, port, err = net.SplitHostPort(v)
				if err != nil {
					log.Printf("unable to open file, url, or address %s: %v", v, err)
					continue
				}
			}

			if host == "" && port != "" {
				host = "localhost"
			}

			addr := net.JoinHostPort(host, port)

			conn, err := tls.Dial("tcp", addr, nil)
			if err != nil {
				log.Printf("unable to open file, url, or address %s: %v", v, err)
				continue
			}

			defer conn.Close()

			state := conn.ConnectionState()

			for i := 0; i < len(state.PeerCertificates); i++ {
				outputCert(state.PeerCertificates[i], opt_out)
			}

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
