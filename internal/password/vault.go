package password

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
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

func(vault *Vault) ProvisionDefaultPrincipals(cfg config.Config) error {

	fmt.Println("provisioning default principals!")
	// create default user principals (such as admin and owner)
	for _, principal := range cfg.Identities.Principals {
		err := vault.CreatePrincipal(principal)
		if err != nil {
			return err
		}
	}

	fmt.Println("provisioning default service principals!")
	// create default service principals for oauth, pki, saml, etc ...
	for _, service := range cfg.Identities.ServicePrincipals {
		err := vault.CreatePrincipal(service.Name)
		if err != nil {
			return err
		}
	}
	
	fmt.Println("provisioning keytabs!")
	// generate keytabs for service principals to enable SPNEGO on startup
	for _, service := range cfg.Identities.ServicePrincipals {
		err := vault.GenerateKeytab(service.Name, cfg.Realm.Name, service.Keytab, cfg.Server.Volume)
		if err != nil {
			return err
		}
	}

	return nil
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
	// vault.mu.RLock()
	// defer vault.mu.RUnlock()

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

func (vault *Vault) GenerateKeytab(service, realm, filename, volume string) error {
	// TODO - use ktutil command to generate keytabs for service principals (NOT principals)
	// https://www.ibm.com/docs/en/pasc/1.1?topic=file-creating-kerberos-principal-keytab
	// printf "%b" "addent -password -p scorpio/admin@SCORPIO.IO -k 1 -e aes256-cts-hmac-sha1-96\nresetme\nwkt scorpio-test.keytab" | ktutil
	
	// lock & unlock ktutil
	vault.mu.Lock()
	defer vault.mu.Unlock()

	password, err := vault.RetrievePassword(service)
	if err != nil {
		return err
	}

	// cmd := `addent -password -p ` + service + ` -k 1 -e aes256-cts-hmac-sha1-96\n` + password + `\nwkt ` + volume + `/` + filename + ` | ktutil`
	// fmt.Println(cmd)

	// TODO: assess JCMTURNER v8 Dependency - https://github.com/jcmturner/gokrb5/tree/master/v8
	kt := keytab.New()
	ts := time.Now()

	err = kt.AddEntry(service, realm, password, ts, uint8(1), etypeID.AES256_CTS_HMAC_SHA1_96)
	if err != nil {
		return err
	}

	generated, err := kt.Marshal()
	if err != nil {
		return err
	}

	// TODO: Permission keytab file correctly 
	os.WriteFile(volume+"/"+filename, generated, 0777)
	if err != nil {
		return err
	}

	return nil
}

// TODO: Add length and runes to config
func generatePassword(n int) string {
    b := make([]rune, n)
    for i := range b {
        b[i] = letterRunes[rand.Intn(len(letterRunes))]
    }
    return string(b)
}

// Kerberos Principal Swagger Documentation
//
// @Summary Manage User & Service Principal KDC identities 
// @Description Allows an owner or admin to create & delete Kerberos principals. Principals are the primary identifiers for Kerberos entities (users, devices, & applications)
// @Tags kerberos
// @Accept application/x-www-form-urlencoded
// @Param principal    query string true "must be set to a unique principal name when creating or an existing principal name when deleting"
//
// @Success	200 {string} string "OK" 
// @Failure 400 {string} string "Bad Request"
// @Failure 415 {string} string "Unsupported Media Type" 
// @Failure 500 {string} string "Internal Server Error" 
//
// @Router /krb/principal [post]
// @Router /krb/principal [delete]
//
// PrincipalHandler as described in https://web.mit.edu/kerberos/kfw-4.1/kfw-4.1/kfw-4.1-help/html/principals.htm
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

	// TODO: implement a GET to query principals

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

// KRB5 Ticket Granting Ticket (TGT) Swagger Documentation
//
// @Summary Generates a principal TGT given an OAuth JWT with matching subject claim
// @Description Ticket Granting Tickets (TGTs) are used by Kerberos clients to obtain Service Tickets (STs) when performing a Ticket Granting Server (TGS) exchange with the KDC.
// @Tags kerberos
// @Accept application/x-www-form-urlencoded
// @Produce application/octet-stream
// @Param principal    query string true "must be set to existing service principal name"
//
// @Success	200 {string} string "OK" 
// @Failure 400 {string} string "Bad Request"
// @Failure 415 {string} string "Unsupported Media Type" 
// @Failure 500 {string} string "Internal Server Error"
//
// @Router /krb/tgt [post]
//
// Krb5TGTHandler as described in https://web.mit.edu/kerberos/krb5-1.12/doc/basic/ccache_def.html
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
