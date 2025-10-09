package password

import (
	"encoding/json"
	"log"
	"net/http"
)

func (v *Vault) MetadataHandler(w http.ResponseWriter, r *http.Request) {
	
	// FIXME move CORS URLs to config
	// check CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Headers", "*")
        return
    }

	// return JSON representation of principal store
	w.Header().Set("Content-Type", "application/json")

	content, err := json.Marshal(v.metadata)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatal(err)
	}

	w.Write(content)
}