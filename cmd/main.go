package main

import (
	"log"
	"net/http"
	"os"
	"runtime"

	"github.com/scorpio-id/kerberos/internal/config"
	"github.com/scorpio-id/kerberos/internal/krb5conf"
	"github.com/scorpio-id/kerberos/internal/transport"
)

// @title Scorpio Kerberos
// @version 1.0
// @description a Go Kerberos realm & client implementation
// @termsOfService http://swagger.io/terms/

// @securityDefinitions.oauth2 OAuth2

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name MIT
// @license.url https://mit-license.org
func main() {

	// FIXME: provide new random seed
	// rand.Seed(time.Now().UnixNano())

	// parse local config (could be added as cmd line arg)
	cfg := config.NewConfig("internal/config/local.yml")
 
	// load default kr5b.conf
	conf, err := os.ReadFile("internal/config/krb5.conf")
	if err != nil {
		log.Fatal(err)
	}

	// parse default krb5.conf
	krb5, err := krb5conf.NewConfigFromString(string(conf))
	if err != nil {
		log.Fatal(err)
	}

	// create a new mux router using config and krb5.conf
	router := transport.NewRouter(cfg, krb5)

	// start the server
	if runtime.GOOS == "linux" {
		log.Fatal(http.ListenAndServeTLS(":"+cfg.Server.Port, "/etc/ssl/certs/scorpio-kerberos.pem", "/etc/ssl/certs/scorpio-kerberos.key", router))
	} else {
		log.Fatal(http.ListenAndServe(":"+cfg.Server.Port, router))
	}
}
