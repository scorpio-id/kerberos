package kadmin

import (
	"bytes"
	"fmt"
	"net/http"
	"os/exec"
	"sync"
)

type Kadmin struct {
	Password string
	mu      sync.RWMutex
}

func (kadmin *Kadmin) CreatePrincipal(principal string, password string) error {
	// set up command 
	cmd := exec.Command("kadmin", "-w", "resetme", "add_principal", "-pw", password, principal)
    var out bytes.Buffer
    cmd.Stdout = &out

	// lock & unlock kadmin
	kadmin.mu.Lock()
	defer kadmin.mu.Unlock()

	// execute command
    err := cmd.Run()
	if err != nil {
		return err
	}

	// all good!
	return nil
}

// web handler
func PrincipalHandler(w http.ResponseWriter, r *http.Request) {
	
	kadmin := Kadmin {
		Password: "resetme",
	}

	err := kadmin.CreatePrincipal("hello-from-golang", "resetme")
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(500)
	}
}