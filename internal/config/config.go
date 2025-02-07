package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port   string `yaml:"port"`
		Host   string `yaml:"host"`
		Volume string `yaml:"volume"`
	} `yaml:"server"`
	OAuth struct {
		Enabled        bool     `yaml:"enabled"`
		TrustedIssuers []string `yaml:"trusted_issuers"`
	} `yaml:"oauth"`
	Realm struct {
		Name             string `yaml:"name"`
		PasswordRotation string `yaml:"password_rotation"`
		PasswordLength   int    `yaml:"password_length"`
	} `yaml:"realm"`
	Identities struct {
		Principals        []string           `yaml:"principals"`
		ServicePrincipals []ServicePrincipal `yaml:"service_principals"`
	} `yaml:"identities"`
}

type ServicePrincipal struct {
	Name   		string `yaml:"name"`
	Keytab 		string `yaml:"keytab"`
	Passfile	string `yaml:"passfile"`
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

	return cfg
}
