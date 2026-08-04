package config

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port   string `yaml:"port" json:"port"`
		Host   string `yaml:"host" json:"host"`
	} `yaml:"server" json:"server"`
	OAuth struct {
		Enabled        bool     `yaml:"enabled" json:"enabled"`
		TrustedIssuers []string `yaml:"trusted_issuers" json:"trusted_issuers"`
	} `yaml:"oauth" json:"oauth"`
	Realm struct {
		Name             string `yaml:"name" json:"name"`
		PasswordRotation string `yaml:"password_rotation" json:"password_rotation"`
		PasswordLength   int    `yaml:"password_length" json:"password_length"`
	} `yaml:"realm" json:"realm"`
	Identities struct {
		Principals        []string           `yaml:"principals" json:"principals"`
		ServicePrincipals []ServicePrincipal `yaml:"service_principals" json:"service_principals"`
	} `yaml:"identities" json:"identities"`
	SPNEGO struct {
		Realm                string `yaml:"realm" json:"realm"`
		ServicePrincipalName string `yaml:"service_principal_name" json:"service_principal_name"`
		Password             string `yaml:"password" json:"-"`
	} `yaml:"spnego" json:"spnego"`
	PKI struct {
		Endpoint             string   `yaml:"endpoint" json:"endpoint"`
		ServicePrincipalName string   `yaml:"service_principal_name" json:"service_principal_name"`
		SANs                 []string `yaml:"sans" json:"sans"`
	} `yaml:"pki" json:"pki"`
	Persistence struct {
		Enabled  bool   `yaml:"enabled" json:"enabled"`
		Port     string `yaml:"port" json:"port"`
		Host     string `yaml:"host" json:"host"`
		User     string `yaml:"user" json:"user"`
		Path     string `yaml:"path" json:"path"`
		Password string `yaml:"-" json:"-"` // DO NOT MARSHAL PASSWORD!
		Database int    `yaml:"database" json:"database"`
	} `yaml:"persistence" json:"persistence"`
}

type ServicePrincipal struct {
	Name   		string `yaml:"name" json:"name"`
	Password	string `yaml:"password" json:"-"`
}

// NewConfig takes a .yml filename from the same /config directory, and returns a populated configuration
func NewConfig(s string) Config {
	f, err := os.Open(s)
	if err != nil {
		log.Fatal(err)
	}

	defer f.Close()

	var cfg Config
	decoder := yaml.NewDecoder(f)

	err = decoder.Decode(&cfg)
	if err != nil {
		log.Fatal(err)
	}

	// TODO retrieve content from Kube Secrets using configured file paths if persistence enabled
	if cfg.Persistence.Enabled {
		content, err := os.ReadFile(cfg.Persistence.Path)
		if err != nil {
			log.Fatalf("Error reading file: %v", err)
		}

		cfg.Persistence.Password = string(content)
	}

	return cfg
}

func (conf *Config) ConfigHandler(w http.ResponseWriter, r *http.Request) {
	// FIXME move CORS URLs to config
	// check CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Headers", "*")
        return
    }

	// return JSON representation of client id store
	w.Header().Set("Content-Type", "application/json")

	content, err := json.Marshal(conf)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Fatal(err)
	}

	w.Write(content)
}