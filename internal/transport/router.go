package transport

import (
	"github.com/gorilla/mux"

	"github.com/scorpio-id/kerberos/internal/config"
)


// NewRouter creates a new mux router with applied server
func NewRouter(cfg config.Config) *mux.Router{

	router := mux.NewRouter()

	// apply OAuth middleware if enabled
	if cfg.OAuth.Enabled {
		om := OAuthMiddleware {
			TrustedIssuers: cfg.OAuth.TrustedIssuers,
		}

		router.Use(om.Middleware)
	}

	return router
}