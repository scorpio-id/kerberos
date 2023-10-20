package main

import (
	"log"
	"net/http"
	"os"

	"github.com/scorpio-id/kerberos/internal/config"
	"github.com/scorpio-id/kerberos/internal/transport"
	jcmconfig "github.com/jcmturner/gokrb5/v8/config"
)

func main() {
	// parse local config (could be added as cmd line arg)
	cfg := config.NewConfig("internal/config/local.yml")

	// load default kr5b.conf
	conf, err := os.ReadFile("internal/config/krb5.conf")
	if err != nil {
		log.Fatalf(err.Error())
	}

	// FIXME - use this, not the jcmturner implementation
	// parse default krb5.conf
	// krb5, err := krb5conf.NewConfigFromString(string(conf))
	// if err != nil {
	// 	log.Fatalf(err.Error())
	// }

	krb5, err := jcmconfig.NewFromString(string(conf))

	// create a new mux router using config and krb5.conf
	router := transport.NewRouter(cfg, krb5)

	// start the server
	log.Fatal(http.ListenAndServe(":"+cfg.Server.Port, router))
}
