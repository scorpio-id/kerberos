package kadmin

import (
	"bytes"
	"fmt"
	"math/rand"
	"net/http"
	"os/exec"
	"sync"

	"github.com/scorpio-id/kerberos/internal/config"
)

var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")


type Vault struct {
	store    *Store
	password string
	cmd      *exec.Cmd
	mu       sync.RWMutex
}

func NewVault(cfg config.Config, password string) (*Vault, error) {
	store, err := NewStore(cfg)
	if err != nil {
		return nil, err
	}

	vault := &Vault{
		store: store,
		password: password,
		cmd:      &exec.Cmd{},
	}

	return vault, nil
}

// TODO: Add length and runes to config
func generatePassword(n int) string {
    b := make([]rune, n)
    for i := range b {
        b[i] = letterRunes[rand.Intn(len(letterRunes))]
    }
    return string(b)
}


func (vault *Vault) CreatePrincipal(principal string) error {
	// lock & unlock kadmin
	vault.mu.Lock()
	defer vault.mu.Unlock()

	// TODO check to ensure the principal name is unique and conforms to MIT standards
	password := generatePassword(18)

	// set up command
	vault.cmd = exec.Command("kadmin", "-w", vault.password, "add_principal", "-pw", password, principal)
	var out bytes.Buffer
	vault.cmd.Stdout = &out

	// execute command
	err := vault.cmd.Run()
	if err != nil {
		return err
	}

	// stores the principal with metadata
	vault.store.Add("scorpio", principal, password)

	// reset command buffer
	vault.cmd = &exec.Cmd{}

	return nil
}

// TODO: Review ACLs - https://docs.oracle.com/cd/E36784_01/html/E37126/aadmin-14.html#scrolltoc
func (vault *Vault) DeletePrincipal(principal string) error {
	// lock & unlock kadmin
	vault.mu.Lock()
	defer vault.mu.Unlock()

	// set up command
	vault.cmd = exec.Command("kadmin", "-w", vault.password, "delete_principal", "-force", principal)
	var out bytes.Buffer
	vault.cmd.Stdout = &out

	// execute command
	err := vault.cmd.Run()
	if err != nil {
		return err
	}
	
	// remove principal from store
	vault.store.Delete(principal)

	// reset command buffer
	vault.cmd = &exec.Cmd{}

	return nil
}

func (vault *Vault) ChangePrincipalPassword(principal string, newpass string) error {
	// lock & unlock kadmin
	vault.mu.Lock()
	defer vault.mu.Unlock()

	// set up command
	vault.cmd = exec.Command("kadmin", "-w", vault.password, "change_password", "-pw", newpass, principal)
	var out bytes.Buffer
	vault.cmd.Stdout = &out

	// execute command
	err := vault.cmd.Run()
	if err != nil {
		return err
	}
	
	// TODO: update store

	// reset command buffer
	vault.cmd = &exec.Cmd{}

	return nil
}

// PrincipalHandler
func (vault *Vault) PrincipalHandler(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	// FIXME: take from JWT subject header using OAuth middleware instead of form data
	principal := r.FormValue("principal")
	if principal == "" {
		w.WriteHeader(http.StatusBadRequest)
	}

	if r.Method == "POST" {
		err := vault.CreatePrincipal(principal)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}

	if r.Method == "DELETE" {
		err := vault.DeletePrincipal(principal)
		if err != nil {
			fmt.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
		}
	}
}
