package metadata

import "sync"

type Store struct {
	AccessControlList map[string]string `json:"access_control_list"`
	Accounts          []Account         `json:"accounts"`
	mu                sync.RWMutex      `json:"-"`
}

type Account struct {
	PrincipalName      string `json:"principal_name"`
	EncryptionType     string `json:"encryption_type"`
	DateCreated        string `json:"date_created"`
	IsServicePrincipal bool   `json:"is_service_principal"`
}

// TODO basic CRUD operations