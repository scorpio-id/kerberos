package kdc

import (
	"encoding/asn1"
	"time"
	"github.com/scorpio-id/kerberos/internal/types"
)

type Ticket struct {
	TktVNO           int                 `asn1:"explicit,tag:0"`
	Realm            string              `asn1:"generalstring,explicit,tag:1"`
	SName            types.PrincipalName `asn1:"explicit,tag:2"`
	EncPart          types.EncryptedData `asn1:"explicit,tag:3"`
	DecryptedEncPart EncTicketPart       `asn1:"optional"` // Not part of ASN1 bytes so marked as optional so unmarshalling works
}

type EncTicketPart struct {
	Flags             asn1.BitString          `asn1:"explicit,tag:0"`
	Key               types.EncryptionKey     `asn1:"explicit,tag:1"`
	CRealm            string                  `asn1:"generalstring,explicit,tag:2"`
	CName             types.PrincipalName     `asn1:"explicit,tag:3"`
	Transited         TransitedEncoding       `asn1:"explicit,tag:4"`
	AuthTime          time.Time               `asn1:"generalized,explicit,tag:5"`
	StartTime         time.Time               `asn1:"generalized,explicit,optional,tag:6"`
	EndTime           time.Time               `asn1:"generalized,explicit,tag:7"`
	RenewTill         time.Time               `asn1:"generalized,explicit,optional,tag:8"`
	CAddr             types.HostAddresses     `asn1:"explicit,optional,tag:9"`
	AuthorizationData types.AuthorizationData `asn1:"explicit,optional,tag:10"`
}

type TransitedEncoding struct {
	TRType   int32  `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}
