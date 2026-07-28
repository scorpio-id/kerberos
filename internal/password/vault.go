package password

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/scorpio-id/kerberos/internal/client"
	"github.com/scorpio-id/kerberos/internal/config"
	"github.com/scorpio-id/kerberos/internal/credentials"
	"github.com/scorpio-id/kerberos/internal/krb5conf"
	"github.com/scorpio-id/kerberos/internal/messages"
	"github.com/scorpio-id/kerberos/internal/metadata"
	"github.com/scorpio-id/kerberos/internal/types"
)

type Vault struct {
	store    *Store
	metadata *metadata.Store
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

	// create metadata store
	principals := metadata.NewStore()

	vault := &Vault{
		store:    store,
		metadata: principals,
		password: password,
		plength:  cfg.Realm.PasswordLength,
		krb5:     krb5,
		cmd:      &exec.Cmd{},
	}

	return vault, nil
}

func (vault *Vault) ProvisionDefaultPrincipals(cfg config.Config) error {

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
		err := vault.CreatePrincipalWithPassword(service.Name, service.Password)
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
	vault.cmd = exec.Command("kadmin.local", "-w", vault.password, "add_principal", "-pw", password, principal)
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

	// FIXME determine if principal is service or user principal
	a := metadata.NewAccount(principal, vault.krb5.LibDefaults.DefaultTGSEnctypes[0], true)
	vault.metadata.Add(a)

	// reset command buffer
	vault.cmd = &exec.Cmd{}

	return nil
}

func (vault *Vault) CreatePrincipalWithPassword(principal, password string) error {
	// lock & unlock kadmin
	vault.mu.Lock()
	defer vault.mu.Unlock()

	// set up command
	vault.cmd = exec.Command("kadmin.local", "-w", vault.password, "add_principal", "-pw", password, principal)
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

	// add account to metadata principal store for admin API
	// FIXME determine if principal is service or user principal
	a := metadata.NewAccount(principal, vault.krb5.LibDefaults.DefaultTGSEnctypes[0], true)
	vault.metadata.Add(a)

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
	vault.cmd = exec.Command("kadmin.local", "-w", vault.password, "delete_principal", "-force", principal)
	var out bytes.Buffer
	vault.cmd.Stdout = &out

	// execute command
	err := vault.cmd.Run()
	if err != nil {
		return err
	}

	// remove principal from store
	vault.store.Delete(principal)

	// remove principal from metadata
	vault.metadata.Delete(principal)

	// reset command buffer
	vault.cmd = &exec.Cmd{}

	return nil
}

func (vault *Vault) ChangePrincipalPassword(principal string, newpass string) error {
	// lock & unlock kadmin
	vault.mu.Lock()
	defer vault.mu.Unlock()

	// set up command
	vault.cmd = exec.Command("kadmin.local", "-w", vault.password, "change_password", "-pw", newpass, principal)
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
	err = os.WriteFile(volume+"/"+filename, generated, 0777)
	if err != nil {
		return err
	}

	return nil
}

func (vault *Vault) AuditPrincipals() {
	// TODO implement, use kadmin to list princs and reconcile with store
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
	w.Header().Set("Content-Disposition", "attachment; filename=\"scorpio.ccache\"")

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
	// FIXME
	login := client.NewClientWithPassword(principal, "KRB.SCORPIO.ORDINARYCOMPUTING.COM", password, vault.krb5)

	// old way: r.Header.Get("subject")
	cname := types.NewPrincipalName(types.KRB_NT_SRV_INST, principal)

	message, err := messages.NewASReqForTGT("KRB.SCORPIO.ORDINARYCOMPUTING.COM", vault.krb5, cname)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// TODO: add realm to config.go
	tgt, err := login.ASExchange("KRB.SCORPIO.ORDINARYCOMPUTING.COM", message, 1)
	if err != nil {
		log.Fatalf("%v", err)
	}

	// TGT bytes
	tgtbytes, err := tgt.Ticket.Marshal()
	if err != nil {
		log.Fatalf("%v", err)
	}

	// CREATE CCACHE
	// https://web.mit.edu/kerberos/krb5-latest/doc/formats/ccache_file_format.html

	// start by creating header field content
	// header tag field
	tag, err := strconv.ParseInt("0x0001", 0, 32)
	if err != nil {
		log.Fatalf("%v", err)
	}

	ftag := uint16(tag)

	// header length field
	length, err := strconv.ParseInt("0x0004", 0, 32)
	if err != nil {
		log.Fatalf("%v", err)
	}

	flength := uint16(length)

	// header value field
	data, err := hex.DecodeString("0x00000000")
	if err !=nil {
		log.Fatalf("%v", err)
	}

	// header field
	first := credentials.HeaderField {
		Tag:    ftag,
		Length: flength,
		Value:  data,
	}

	hlength, err := strconv.ParseInt("0x000c", 0, 32)
	if err != nil {
		log.Fatalf("%v", err)
	}

	headerLength := uint16(hlength)

	// create header
	header := credentials.Header {
		Length: headerLength,
		Fields: []credentials.HeaderField{first},
	}

	version, err := strconv.ParseInt("0x0504", 0, 32)
	if err != nil {
		log.Fatalf("%v", err)
	}

	cversion := uint8(version)

	// create Principal struct (using 1 for known name instead of 0 unknown)
	// TODO check if principal name string needs realm name
	ptype := types.PrincipalName {
		NameType: 1,
		NameString: []string{principal},
	}

	cprincipal := credentials.Principal {
		Realm: vault.krb5.LibDefaults.DefaultRealm,
		PrincipalName: ptype,
	}

	// create Credential struct (NOTE: server principal is currently empty)
	ccredential := credentials.Credential {
		Client: cprincipal,
		// Server: credentials.Principal{},
		// Key: types.EncryptionKey{},
		// AuthTime: time.Now(),
		// StartTime: time.Now(),
		// EndTime: time.Now().AddDate(0, 0, 7),
		// RenewTill: time.Now().AddDate(0, 0, 30),
		IsSKey: false,
		Ticket: tgtbytes,
	}

	// set path

	// TODO finish creating CCache file!
	ccache := credentials.CCache {
		Version: cversion,
		Header:  header,
		DefaultPrincipal: cprincipal,
		Credentials: []*credentials.Credential{&ccredential},
	}

	// convert ccache struct into []byte
	buff := new(bytes.Buffer)
	
	// Write serializes the struct into the buffer
	err = binary.Write(buff, binary.BigEndian, ccache)
	if err != nil {
		log.Fatal(err)
	}

	// return ccache binary content as []bytes
	w.Write(buff.Bytes())
}
