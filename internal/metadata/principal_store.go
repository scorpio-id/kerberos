package metadata

import (
	"sync"
	"time"
)

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

// TODO document
func NewStore() *Store {
	return &Store {
		AccessControlList: make(map[string]string),
		Accounts: make([]Account, 0),
	}
}

func NewAccount(principal, enctype string, isService bool) Account {
	now := time.Now().UTC().Format(time.RFC1123)
	return Account {
		PrincipalName: principal,
		EncryptionType: enctype,
		DateCreated: now,
		IsServicePrincipal: isService,
	}
}

func(s *Store) Add(a Account) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Accounts = append(s.Accounts, a)
}

func(s *Store) Delete(principal string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i, v := range s.Accounts {
		if v.PrincipalName == principal {
			s.Accounts = append(s.Accounts[:i], s.Accounts[i+1:]...)
			break
		}
	}
}

func(s *Store) Contains(principal string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, v := range(s.Accounts) {
		if v.PrincipalName == principal {
			return true
		}
	}

	return false
}