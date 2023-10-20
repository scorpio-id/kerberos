package transport

import (
	"fmt"
	"log"

	"github.com/gorilla/mux"

	"github.com/jcmturner/gokrb5/v8/client"
	jcmconfig "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/scorpio-id/kerberos/internal/config"
)

// NewRouter creates a new mux router with applied server
func NewRouter(cfg config.Config, krb5 *jcmconfig.Config) *mux.Router {

	router := mux.NewRouter()

	// create krb5client to login to KDC
	krb5client := client.NewWithPassword("scorpio", "SCORPIO.IO", "resetme", krb5)
	err := krb5client.Login()
	if err != nil {
		log.Fatal(err)
	}

	uprincipal := types.PrincipalName {
		NameType: 1,
		NameString: []string{"scorpio"},
	}

	// aprincipal := types.PrincipalName {
	// 	NameType: 1,
	// 	NameString: []string{"test-service/test-service.scorpio.io"},
	// }

	req, err := messages.NewASReqForTGT("SCORPIO.IO", krb5, uprincipal)

	res, err := krb5client.ASExchange("SCORPIO.IO", req, 0)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("successful: " + res.Ticket.Realm)

	// router.HandleFunc("/krb5conf", krb5.Krb5ConfHandler).Methods(http.MethodGet, http.MethodOptions)

	// apply OAuth middleware if enabled
	if cfg.OAuth.Enabled {
		om := OAuthMiddleware{
			TrustedIssuers: cfg.OAuth.TrustedIssuers,
		}

		router.Use(om.Middleware)
	}

	return router
}
