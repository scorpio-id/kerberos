package types

// Address type IDs.

const (
	IPv4                       int32 = 2
	Directional                int32 = 3
	ChaosNet                   int32 = 5
	XNS                        int32 = 6
	ISO                        int32 = 7
	DECNETPhaseIV              int32 = 12
	AppleTalkDDP               int32 = 16
	NetBios                    int32 = 20
	IPv6                       int32 = 24
	KRB_NT_UNKNOWN             int32 = 0  //Name type not known
	KRB_NT_PRINCIPAL           int32 = 1  //Just the name of the principal as in DCE,  or for users
	KRB_NT_SRV_INST            int32 = 2  //Service and other unique instance (krbtgt)
	KRB_NT_SRV_HST             int32 = 3  //Service with host name as instance (telnet, rcommands)
	KRB_NT_SRV_XHST            int32 = 4  //Service with host as remaining components
	KRB_NT_UID                 int32 = 5  //Unique ID
	KRB_NT_X500_PRINCIPAL      int32 = 6  //Encoded X.509 Distinguished name [RFC2253]
	KRB_NT_SMTP_NAME           int32 = 7  //Name in form of SMTP email name (e.g., user@example.com)
	KRB_NT_ENTERPRISE          int32 = 10 //Enterprise name; may be mapped to principal name
	PA_TGS_REQ                 int32 = 1
	PA_ENC_TIMESTAMP           int32 = 2
	PA_PW_SALT                 int32 = 3
	PA_ENC_UNIX_TIME           int32 = 5
	PA_SANDIA_SECUREID         int32 = 6
	PA_SESAME                  int32 = 7
	PA_OSF_DCE                 int32 = 8
	PA_CYBERSAFE_SECUREID      int32 = 9
	PA_AFS3_SALT               int32 = 10
	PA_ETYPE_INFO              int32 = 11
	PA_SAM_CHALLENGE           int32 = 12
	PA_SAM_RESPONSE            int32 = 13
	PA_PK_AS_REQ_OLD           int32 = 14
	PA_PK_AS_REP_OLD           int32 = 15
	PA_PK_AS_REQ               int32 = 16
	PA_PK_AS_REP               int32 = 17
	PA_PK_OCSP_RESPONSE        int32 = 18
	PA_ETYPE_INFO2             int32 = 19
	PA_USE_SPECIFIED_KVNO      int32 = 20
	PA_SVR_REFERRAL_INFO       int32 = 20
	PA_SAM_REDIRECT            int32 = 21
	PA_GET_FROM_TYPED_DATA     int32 = 22
	TD_PADATA                  int32 = 22
	PA_SAM_ETYPE_INFO          int32 = 23
	PA_ALT_PRINC               int32 = 24
	PA_SERVER_REFERRAL         int32 = 25
	PA_SAM_CHALLENGE2          int32 = 30
	PA_SAM_RESPONSE2           int32 = 31
	PA_EXTRA_TGT               int32 = 41
	TD_PKINIT_CMS_CERTIFICATES int32 = 101
	TD_KRB_PRINCIPAL           int32 = 102
	TD_KRB_REALM               int32 = 103
	TD_TRUSTED_CERTIFIERS      int32 = 104
	TD_CERTIFICATE_INDEX       int32 = 105
	TD_APP_DEFINED_ERROR       int32 = 106
	TD_REQ_NONCE               int32 = 107
	TD_REQ_SEQ                 int32 = 108
	TD_DH_PARAMETERS           int32 = 109
	TD_CMS_DIGEST_ALGORITHMS   int32 = 111
	TD_CERT_DIGEST_ALGORITHMS  int32 = 112
	PA_PAC_REQUEST             int32 = 128
	PA_FOR_USER                int32 = 129
	PA_FOR_X509_USER           int32 = 130
	PA_FOR_CHECK_DUPS          int32 = 131
	PA_AS_CHECKSUM             int32 = 132
	PA_FX_COOKIE               int32 = 133
	PA_AUTHENTICATION_SET      int32 = 134
	PA_AUTH_SET_SELECTED       int32 = 135
	PA_FX_FAST                 int32 = 136
	PA_FX_ERROR                int32 = 137
	PA_ENCRYPTED_CHALLENGE     int32 = 138
	PA_OTP_CHALLENGE           int32 = 141
	PA_OTP_REQUEST             int32 = 142
	PA_OTP_CONFIRM             int32 = 143
	PA_OTP_PIN_CHANGE          int32 = 144
	PA_EPAK_AS_REQ             int32 = 145
	PA_EPAK_AS_REP             int32 = 146
	PA_PKINIT_KX               int32 = 147
	PA_PKU2U_NAME              int32 = 148
	PA_REQ_ENC_PA_REP          int32 = 149
	PA_AS_FRESHNESS            int32 = 150
	PA_SUPPORTED_ETYPES        int32 = 165
	PA_EXTENDED_ERROR          int32 = 166
	//RESERVED : 0
	DES_CBC_CRC                  int32 = 1
	DES_CBC_MD4                  int32 = 2
	DES_CBC_MD5                  int32 = 3
	DES_CBC_RAW                  int32 = 4
	DES3_CBC_MD5                 int32 = 5
	DES3_CBC_RAW                 int32 = 6
	DES3_CBC_SHA1                int32 = 7
	DES_HMAC_SHA1                int32 = 8
	DSAWITHSHA1_CMSOID           int32 = 9
	MD5WITHRSAENCRYPTION_CMSOID  int32 = 10
	SHA1WITHRSAENCRYPTION_CMSOID int32 = 11
	RC2CBC_ENVOID                int32 = 12
	RSAENCRYPTION_ENVOID         int32 = 13
	RSAES_OAEP_ENV_OID           int32 = 14
	DES_EDE3_CBC_ENV_OID         int32 = 15
	DES3_CBC_SHA1_KD             int32 = 16
	AES128_CTS_HMAC_SHA1_96      int32 = 17
	AES256_CTS_HMAC_SHA1_96      int32 = 18
	AES128_CTS_HMAC_SHA256_128   int32 = 19
	AES256_CTS_HMAC_SHA384_192   int32 = 20
	//UNASSIGNED : 21-22
	RC4_HMAC             int32 = 23
	RC4_HMAC_EXP         int32 = 24
	CAMELLIA128_CTS_CMAC int32 = 25
	CAMELLIA256_CTS_CMAC int32 = 26
	//UNASSIGNED : 27-64
	SUBKEY_KEYMATERIAL int32 = 65
	//UNASSIGNED : 66-2147483647
)

// ETypesByName is a map of EncType names to their assigned EncType number.
var ETypesByName = map[string]int32{
	"des-cbc-crc":                  DES_CBC_CRC,
	"des-cbc-md4":                  DES_CBC_MD4,
	"des-cbc-md5":                  DES_CBC_MD5,
	"des-cbc-raw":                  DES_CBC_RAW,
	"des3-cbc-md5":                 DES3_CBC_MD5,
	"des3-cbc-raw":                 DES3_CBC_RAW,
	"des3-cbc-sha1":                DES3_CBC_SHA1,
	"des3-hmac-sha1":               DES_HMAC_SHA1,
	"des3-cbc-sha1-kd":             DES3_CBC_SHA1_KD,
	"des-hmac-sha1":                DES_HMAC_SHA1,
	"dsaWithSHA1-CmsOID":           DSAWITHSHA1_CMSOID,
	"md5WithRSAEncryption-CmsOID":  MD5WITHRSAENCRYPTION_CMSOID,
	"sha1WithRSAEncryption-CmsOID": SHA1WITHRSAENCRYPTION_CMSOID,
	"rc2CBC-EnvOID":                RC2CBC_ENVOID,
	"rsaEncryption-EnvOID":         RSAENCRYPTION_ENVOID,
	"rsaES-OAEP-ENV-OID":           RSAES_OAEP_ENV_OID,
	"des-ede3-cbc-Env-OID":         DES_EDE3_CBC_ENV_OID,
	"aes128-cts-hmac-sha1-96":      AES128_CTS_HMAC_SHA1_96,
	"aes128-cts":                   AES128_CTS_HMAC_SHA1_96,
	"aes128-sha1":                  AES128_CTS_HMAC_SHA1_96,
	"aes256-cts-hmac-sha1-96":      AES256_CTS_HMAC_SHA1_96,
	"aes256-cts":                   AES256_CTS_HMAC_SHA1_96,
	"aes256-sha1":                  AES256_CTS_HMAC_SHA1_96,
	"aes128-cts-hmac-sha256-128":   AES128_CTS_HMAC_SHA256_128,
	"aes128-sha2":                  AES128_CTS_HMAC_SHA256_128,
	"aes256-cts-hmac-sha384-192":   AES256_CTS_HMAC_SHA384_192,
	"aes256-sha2":                  AES256_CTS_HMAC_SHA384_192,
	"arcfour-hmac":                 RC4_HMAC,
	"rc4-hmac":                     RC4_HMAC,
	"arcfour-hmac-md5":             RC4_HMAC,
	"arcfour-hmac-exp":             RC4_HMAC_EXP,
	"rc4-hmac-exp":                 RC4_HMAC_EXP,
	"arcfour-hmac-md5-exp":         RC4_HMAC_EXP,
	"camellia128-cts-cmac":         CAMELLIA128_CTS_CMAC,
	"camellia128-cts":              CAMELLIA128_CTS_CMAC,
	"camellia256-cts-cmac":         CAMELLIA256_CTS_CMAC,
	"camellia256-cts":              CAMELLIA256_CTS_CMAC,
	"subkey-keymaterial":           SUBKEY_KEYMATERIAL,
}

// EtypeSupported resolves the etype name string to the etype ID.
// If zero is returned the etype is not supported by gokrb5.
func EtypeSupported(etype string) int32 {
	// Slice of supported enctype IDs
	s := []int32{
		AES128_CTS_HMAC_SHA1_96,
		AES256_CTS_HMAC_SHA1_96,
		AES128_CTS_HMAC_SHA256_128,
		AES256_CTS_HMAC_SHA384_192,
		DES3_CBC_SHA1_KD,
		RC4_HMAC,
	}
	id := ETypesByName[etype]
	if id == 0 {
		return id
	}
	for _, sid := range s {
		if id == sid {
			return id
		}
	}
	return 0
}