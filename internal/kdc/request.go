package kdc

import (
	"encoding/asn1"
	"time"

	"github.com/scorpio-id/kerberos/internal/config"
	"github.com/scorpio-id/kerberos/internal/types"
)

// KDCReqFields represents the KRB_KDC_REQ fields.
type KDCReqFields struct {
	PVNO    int
	MsgType int
	PAData  types.PADataSequence
	ReqBody KDCReqBody
	Renewal bool
}

// KDCReqBody implements the KRB_KDC_REQ request body.
type KDCReqBody struct {
	KDCOptions        asn1.BitString      `asn1:"explicit,tag:0"`
	CName             types.PrincipalName `asn1:"explicit,optional,tag:1"`
	Realm             string              `asn1:"generalstring,explicit,tag:2"`
	SName             types.PrincipalName `asn1:"explicit,optional,tag:3"`
	From              time.Time           `asn1:"generalized,explicit,optional,tag:4"`
	Till              time.Time           `asn1:"generalized,explicit,tag:5"`
	RTime             time.Time           `asn1:"generalized,explicit,optional,tag:6"`
	Nonce             int                 `asn1:"explicit,tag:7"`
	EType             []int32             `asn1:"explicit,tag:8"`
	Addresses         []types.HostAddress `asn1:"explicit,optional,tag:9"`
	EncAuthData       types.EncryptedData `asn1:"explicit,optional,tag:10"`
	AdditionalTickets []Ticket            `asn1:"explicit,optional,tag:11"`
}

// ASReq implements RFC 4120 KRB_AS_REQ: https://tools.ietf.org/html/rfc4120#section-5.4.1.
type ASReq struct {
	KDCReqFields
}

func NewASReqForTGT(realm string, c *config.Config, cname types.PrincipalName) (ASReq, error) {
	sname := types.PrincipalName{
		NameType:   types.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}
	return NewASReq(realm, c, cname, sname)
}
