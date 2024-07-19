package config

import (
	"log"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port string `yaml:"port"`
		Host string `yaml:"host"`
	} `yaml:"server"`
	OAuth struct {
		Enabled        bool     `yaml:"enabled"`
		TrustedIssuers []string `yaml:"trusted_issuers"`
	} `yaml:"oauth"`
	Realm struct {
		Name             string `yaml:"name"`
		PasswordRotation string `yaml:"password_rotation"`
	} `yaml:"realm"`
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
