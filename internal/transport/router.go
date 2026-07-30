package transport

import (
	"log"
	"net/http"
	"runtime"

	"github.com/gorilla/mux"
	_ "github.com/scorpio-id/kerberos/docs"
	"github.com/swaggo/http-swagger/v2"

	"github.com/scorpio-id/kerberos/internal/config"
	"github.com/scorpio-id/kerberos/internal/data"
	"github.com/scorpio-id/kerberos/internal/krb5conf"
	"github.com/scorpio-id/kerberos/internal/password"
	"github.com/scorpio-id/kerberos/internal/tls"
)

// NewRouter creates a new mux router with applied server
func NewRouter(cfg config.Config, krb5 *krb5conf.Krb5Config) *mux.Router {

	router := mux.NewRouter()

	persistClient := data.NewPersistenceClient(cfg)


	// adding swagger 
	router.PathPrefix("/swagger/").Handler(httpSwagger.Handler(
		httpSwagger.URL("http://krb.scorpio.ordinarycomputing.com:" + cfg.Server.Port + "/swagger/doc.json"),
		httpSwagger.DeepLinking(true),
		httpSwagger.DocExpansion("none"),
		httpSwagger.DomID("swagger-ui"),
	)).Methods(http.MethodGet)


	// must have access to kadmin
	// TODO: remove plaintext password
	vault, err := password.NewVault(cfg, krb5, "resetme")
	if err != nil {
		log.Fatal(err)
	}

	// generate keytabs on mounted volumes
	err = vault.ProvisionDefaultPrincipals(cfg)
	if err != nil {
		log.Fatal(err)
	}

	subr := router.PathPrefix("/krb").Subrouter()

	subr.HandleFunc("/conf", krb5.Krb5ConfHandler).Methods(http.MethodGet, http.MethodOptions)
	subr.HandleFunc("/tgt", vault.Krb5TGTHandler).Methods(http.MethodPost, http.MethodOptions)
	subr.HandleFunc("/principal", vault.PrincipalHandler).Methods(http.MethodGet, http.MethodPost, http.MethodDelete, http.MethodOptions)

	// create subrouter for CORS-enabled UIs
	uisubr := router.PathPrefix("/ui").Subrouter()

	// config endpoint for console
	uisubr.HandleFunc("/config", cfg.ConfigHandler).Methods(http.MethodGet, http.MethodOptions)

	// metadata endpoint for console UI
	uisubr.HandleFunc("/metadata", vault.MetadataHandler).Methods(http.MethodGet, http.MethodOptions)

	// enable CORS 
	uisubr.Use(mux.CORSMethodMiddleware(uisubr))

	// apply OAuth middleware if enabled
	if cfg.OAuth.Enabled {
		om := OAuthMiddleware{
			TrustedIssuers: cfg.OAuth.TrustedIssuers,
		}

		subr.Use(om.Middleware)
	}

	// check if TLS is enabled, if so create cert client and serialize x509 if on linux OS
	if runtime.GOOS == "linux" {
		content, err := persistClient.LoadWebPKCS12()
		if err != nil {
			log.Fatal(err)
		}

		// serialize PKCS12 for SSL
		err = tls.SerializePKCS12(content, "/etc/ssl/certs")
		if err != nil {
			log.Fatal(err)
		}
	}

	return router
}
