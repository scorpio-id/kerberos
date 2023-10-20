package types

// TODO: original did not use standard ASN1 https://github.com/jcmturner/gokrb5/blob/master/types/Cryptosystem.go#L4
import (
	"encoding/asn1"
	"strings"
)

// PrincipalName implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.2
type PrincipalName struct {
	NameType   int32    `asn1:"explicit,tag:0"`
	NameString []string `asn1:"generalstring,explicit,tag:1"`
}

// NewPrincipalName creates a new PrincipalName from the name type int32 and name string provided.
func NewPrincipalName(ntype int32, spn string) PrincipalName {
	return PrincipalName{
		NameType:   ntype,
		NameString: strings.Split(spn, "/"),
	}
}

// GetSalt returns a salt derived from the PrincipalName.
func (pn PrincipalName) GetSalt(realm string) string {
	var sb []byte
	sb = append(sb, realm...)
	for _, n := range pn.NameString {
		sb = append(sb, n...)
	}
	return string(sb)
}

// Equal tests if the PrincipalName is equal to the one provided.
func (pn PrincipalName) Equal(n PrincipalName) bool {
	//https://tools.ietf.org/html/rfc4120#section-6.2 - the name type is not significant when checking for equivalence
	for i, s := range pn.NameString {
		if n.NameString[i] != s {
			return false
		}
	}
	return true
}

// PrincipalNameString returns the PrincipalName in string form.
func (pn PrincipalName) PrincipalNameString() string {
	return strings.Join(pn.NameString, "/")
}

// EncryptedData implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.9
type EncryptedData struct {
	EType  int32  `asn1:"explicit,tag:0"`
	KVNO   int    `asn1:"explicit,optional,tag:1"`
	Cipher []byte `asn1:"explicit,tag:2"`
}

// EncryptionKey implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.9
// AKA KeyBlock
type EncryptionKey struct {
	KeyType  int32  `asn1:"explicit,tag:0"`
	KeyValue []byte `asn1:"explicit,tag:1"`
}

// Checksum implements RFC 4120 type: https://tools.ietf.org/html/rfc4120#section-5.2.9
type Checksum struct {
	CksumType int32  `asn1:"explicit,tag:0"`
	Checksum  []byte `asn1:"explicit,tag:1"`
}

// Unmarshal bytes into the EncryptedData.
func (a *EncryptedData) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

// Marshal the EncryptedData.
func (a *EncryptedData) Marshal() ([]byte, error) {
	edb, err := asn1.Marshal(*a)
	if err != nil {
		return edb, err
	}
	return edb, nil
}

// Unmarshal bytes into the EncryptionKey.
func (a *EncryptionKey) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}

// Unmarshal bytes into the Checksum.
func (a *Checksum) Unmarshal(b []byte) error {
	_, err := asn1.Unmarshal(b, a)
	return err
}
