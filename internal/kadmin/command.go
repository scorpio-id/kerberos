package kadmin

import (
	"bytes"
	"fmt"
	"net/http"
	"os/exec"
	"sync"
)

type Kadmin struct {
	password 	string
	cmd	 		*exec.Cmd
	mu       	sync.RWMutex
}

func NewKadmin(password string) *Kadmin {
	return &Kadmin{
		password: "password",
		cmd: &exec.Cmd{},
	}
}

func (kadmin *Kadmin) CreatePrincipal(principal string, password string) error {
	// lock & unlock kadmin
	kadmin.mu.Lock()
	defer kadmin.mu.Unlock()

	// set up command 
	kadmin.cmd = exec.Command("kadmin", "-w", "resetme", "add_principal", "-pw", password, principal)
    var out bytes.Buffer
    kadmin.cmd.Stdout = &out

	// execute command
    err := kadmin.cmd.Run()
	if err != nil {
		return err
	}

	// reset command buffer
	kadmin.cmd = &exec.Cmd{}

	// all good!
	return nil
}

// TODO: Review ACLs - https://docs.oracle.com/cd/E36784_01/html/E37126/aadmin-14.html#scrolltoc
func (kadmin *Kadmin) DeletePrincipal(principal string) error {
	// lock & unlock kadmin
	kadmin.mu.Lock()
	defer kadmin.mu.Unlock()

	// set up command 
	kadmin.cmd = exec.Command("kadmin", "-w", "resetme", "delete_principal", "-force", principal)
    var out bytes.Buffer
    kadmin.cmd.Stdout = &out

	// execute command
    err := kadmin.cmd.Run()
	if err != nil {
		return err
	}

	// reset command buffer
	kadmin.cmd = &exec.Cmd{}

	// all good!
	return nil
}

func (kadmin *Kadmin) ChangePrincipalPassword(principal string, newPassword string) error {
	// lock & unlock kadmin
	kadmin.mu.Lock()
	defer kadmin.mu.Unlock()

	// set up command 
	kadmin.cmd = exec.Command("kadmin", "-w", "resetme", "change_password", "-pw", newPassword, principal)
    var out bytes.Buffer
    kadmin.cmd.Stdout = &out

	// execute command
    err := kadmin.cmd.Run()
	if err != nil {
		return err
	}
	// reset command buffer
	kadmin.cmd = &exec.Cmd{}

	// all good!
	return nil
}

// web handler
func PrincipalHandler(w http.ResponseWriter, r *http.Request) {
	kadmin := Kadmin {
		password: "resetme",
	}

	err := kadmin.CreatePrincipal("hello-from-golang", "resetme")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
	}
}