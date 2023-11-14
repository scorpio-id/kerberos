package transport

import (
	"log"
	"net/http"

	"github.com/gorilla/mux"

	"github.com/scorpio-id/kerberos/internal/client"
	"github.com/scorpio-id/kerberos/internal/config"
	"github.com/scorpio-id/kerberos/internal/krb5conf"
)

// NewRouter creates a new mux router with applied server
func NewRouter(cfg config.Config, krb5 *krb5conf.Krb5Config) *mux.Router {

	router := mux.NewRouter()

	// create krb5client to login to KDC
	admin := client.NewClientWithPassword("scorpio/admin", "SCORPIO.IO", "resetme", krb5)

	// TODO - possibly move into handler and login
	err := admin.Login()
	if err != nil {
		log.Fatalf("%v", err)
	}

	router.HandleFunc("/krb5conf", krb5.Krb5ConfHandler).Methods(http.MethodGet, http.MethodOptions)
	router.HandleFunc("/tgt", admin.Krb5TGTHandler).Methods(http.MethodPost, http.MethodOptions)

	// apply OAuth middleware if enabled
	if cfg.OAuth.Enabled {
		om := OAuthMiddleware{
			TrustedIssuers: cfg.OAuth.TrustedIssuers,
		}

		router.Use(om.Middleware)
	}

	return router
}
