package tls

import (
	"bufio"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"

	"github.com/hetesiistvan/go-pkcs12"
	"github.com/jcmturner/gokrb5/v8/client"
	kconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/spnego"
	"github.com/scorpio-id/kerberos/internal/config"
)

// RetrieveTLSCertificate invokes PKI service to obtain a signed PKCS12 for configured DNS name (ex: oauth.ordinarycomputing.com)
func RetrieveTLSCertificate(cfg config.Config) ([]byte, error) {
	// read password from mounted volume using configured path
	kcfg, err := kconfig.Load("internal/config/krb5.conf")
	if err != nil {
		return nil, err
	}

	// initialize Kerberos client and authenticate for TGT
	cl := client.NewWithPassword(cfg.SPNEGO.ServicePrincipalName, cfg.SPNEGO.Realm, cfg.SPNEGO.Password, kcfg)
	err = cl.Login()
	if err != nil {
		return nil, err
	}

	defer cl.Destroy()

	// submit Kerberos ST to PKI via SPNEGO
	// build query parameters for PKCS12 HTTP request
	destination, err := url.Parse(cfg.PKI.Endpoint)
	if err != nil {
		return nil, err
	}

	q := destination.Query()

	for _, san := range cfg.PKI.SANs {
		q.Add("san", san)
	}

	destination.RawQuery = q.Encode()

	fmt.Println("destination pki url: " + destination.String())

	r, _ := http.NewRequest("POST", destination.String(), nil)
	r.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	// disable SSL for SPNEGO
	customTransport := http.DefaultTransport.(*http.Transport).Clone()
	customTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	httpclient := &http.Client{Transport: customTransport}

	// TODO check if correct SPN 
	spnegocl := spnego.NewClient(cl, httpclient, "HTTP/ca.scorpio.ordinarycomputing.com")
	response, err := spnegocl.Do(r)
	if err != nil {
		log.Default().Print(err.Error())
		return nil, err
	}

	fmt.Println("PKI HTTP Status: " + response.Status)
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

func SerializePKCS12(content []byte, path string) error {
	key, cert, cacerts, err := pkcs12.DecodeChain(content, "")
    if err != nil {
        return err
    }

	// store .cer file on provided filesystem path
	cout, err := os.Create(path + "/scorpio-kerberos.pem")
    if err != nil {
        return err
    }

	defer cout.Close()

	w := bufio.NewWriter(cout)

	leaf := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	// TODO: check to ensure serialized correctly
	err = pem.Encode(w, &leaf)
	if err != nil {
		return err
	}

	root := pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cacerts[0].Raw,
	}

	// TODO: check to ensure serialized correctly
	err = pem.Encode(w, &root)
	if err != nil {
		return err
	}

	w.Flush()

	// store .cer file on provided filesystem path
	kout, err := os.Create(path + "/scorpio-kerberos.key")
    if err != nil {
        return err
    }

	defer kout.Close()

	// FIXME might be incorrect way of converting interface to []byte
	w = bufio.NewWriter(kout)

	private, ok := key.(*rsa.PrivateKey)
	if !ok {
		return errors.New("unable to convert key interface to *rsa.PrivateKey")
	}

	pemkey := pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(private), 
	}

	// TODO: check to ensure serialized correctly
	err = pem.Encode(w, &pemkey)
	if err != nil {
		return err
	}

	w.Flush()

	return nil
}