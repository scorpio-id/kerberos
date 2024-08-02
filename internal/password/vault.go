package password

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os/exec"
	"sync"

	"github.com/scorpio-id/kerberos/internal/client"
	"github.com/scorpio-id/kerberos/internal/config"
	"github.com/scorpio-id/kerberos/internal/krb5conf"
	"github.com/scorpio-id/kerberos/internal/messages"
	"github.com/scorpio-id/kerberos/internal/types"
)

type Vault struct {
	store    *Store
	password string
	plength  int
	krb5     *krb5conf.Krb5Config
	cmd      *exec.Cmd
	mu       sync.RWMutex
}

func NewVault(cfg config.Config, krb5 *krb5conf.Krb5Config, password string) (*Vault, error) {
	store, err := NewStore(cfg)
	if err != nil {
		return nil, err
	}

	vault := &Vault{
		store:    store,
		password: password,
		plength:  cfg.Realm.PasswordLength,
		krb5:     krb5,
		cmd:      &exec.Cmd{},
	}

	return vault, nil
}


func (vault *Vault) CreatePrincipal(principal string) error {
	// lock & unlock kadmin
	vault.mu.Lock()
	defer vault.mu.Unlock()

	// TODO check to ensure the principal name is unique and conforms to MIT standards
	password := generatePassword(vault.plength)

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
	// FIXME: accept clientID
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

func (vault *Vault) RetrievePassword(principal string) (string, error) {
	vault.mu.RLock()
	defer vault.mu.RUnlock()

	// TODO: check if principal exists first
	decoded, err := hex.DecodeString(vault.store.data[principal].encpass)
	if err != nil {
    	fmt.Println("error decoding hex", err)
    	return "", err
	}

	plaintext, err := vault.store.gcm.Open(nil, decoded[:vault.store.gcm.NonceSize()], decoded[vault.store.gcm.NonceSize():], nil)
	if err != nil {
    	fmt.Println("error decrypting ciphertext", err)
    	return "", err
	}

	return string(plaintext), nil
}

// TODO: Add length and runes to config
func generatePassword(n int) string {
    b := make([]rune, n)
    for i := range b {
        b[i] = letterRunes[rand.Intn(len(letterRunes))]
    }
    return string(b)
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

// FIXME - you don't need a client, you just need a krb5config
func (vault *Vault) Krb5TGTHandler(w http.ResponseWriter, r *http.Request) {
	// return .conf file type
	w.Header().Set("Content-Type", "application/octet-stream")

	// get principal name from request form params
	// TODO: get principal name from JWT claims instead of form param
	if r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		w.WriteHeader(http.StatusUnsupportedMediaType)
		return
	}

	// FIXME: take from JWT subject header using OAuth middleware instead of form data
	principal := r.FormValue("principal")
	if principal == "" {
		w.WriteHeader(http.StatusBadRequest)
	}

	// start by retrieving password
	password, err := vault.RetrievePassword(principal)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
	}

	// log in
	login := client.NewClientWithPassword(principal, "SCORPIO.IO", password, vault.krb5)

	// old way: r.Header.Get("subject")
	cname := types.NewPrincipalName(types.KRB_NT_SRV_INST, principal)

	message, err := messages.NewASReqForTGT("SCORPIO.IO", vault.krb5, cname)
	if err != nil{
		log.Fatalf("%v", err)
	}

	// TODO: add realm to config.go
	tgt, err := login.ASExchange("SCORPIO.IO", message, 1)
	if err != nil{
		log.Fatalf("%v", err)
	}

	bytes, err := tgt.Ticket.Marshal()
	if err != nil{
		log.Fatalf("%v", err)
	}

	w.Write(bytes)
}
