package kadmin

import (
	"bytes"
	"fmt"
	"net/http"
	"os/exec"
	"sync"
)

type Vault struct {
	password string
	cmd      *exec.Cmd
	mu       sync.RWMutex
}

func NewVault(password string) *Vault {
	return &Vault{
		password: password,
		cmd:      &exec.Cmd{},
	}
}

func (vault *Vault) CreatePrincipal(principal string, password string) error {
	// lock & unlock kadmin
	vault.mu.Lock()
	defer vault.mu.Unlock()

	// set up command
	vault.cmd = exec.Command("kadmin", "-w", vault.password, "add_principal", "-pw", password, principal)
	var out bytes.Buffer
	vault.cmd.Stdout = &out

	// execute command
	err := vault.cmd.Run()
	if err != nil {
		return err
	}

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
		err := vault.CreatePrincipal(principal, "resetme")
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
