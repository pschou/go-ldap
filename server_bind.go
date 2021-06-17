package ldap

import (
	ber "github.com/go-asn1-ber/asn1-ber"
	"net"
)

// Other LDAP constants
const (
	LDAPBindAuthSimple = 0
	LDAPBindAuthSASL   = 3
)

type DeleteRequest struct {
	dn string
}
type AttributeValueAssertion struct {
	attributeDesc  string
	assertionValue string
}
type ExtendedRequest struct {
	requestName  string
	requestValue string
}

func HandleBindRequest(req *ber.Packet, bindSpec BindSpec, fns map[string]Binder, conn net.Conn) (resultCode uint16) {
	defer func() {
		if r := recover(); r != nil {
			resultCode = LDAPResultOperationsError
		}
	}()

	//log.Println("DEBUG binddn ")
	// we only support ldapv3
	ldapVersion, ok := req.Children[0].Value.(int64)
	if !ok {
		bindSpec.Server.Debug.Println("Invalid init packet.")
		return LDAPResultProtocolError
	}

	// Check that the version is enabled / supported
	if (ldapVersion == 2 && !bindSpec.Server.EnableV2) ||
		(ldapVersion == 3 && !bindSpec.Server.EnableV3) ||
		(ldapVersion < 2 || ldapVersion > 3) {
		bindSpec.Server.Debug.Printf("Unsupported LDAP version: %d", ldapVersion)
		return LDAPResultInappropriateAuthentication
	}

	bindSpec.Server.Debug.Printf("LDAP version: %d", ldapVersion)

	// TODO: what if BindDN is not specified
	// auth types
	bindDN, ok := req.Children[1].Value.(string)
	bindSpec.BindDN = bindDN
	//log.Println("DEBUG binddn ", bindDN)
	if !ok {
		bindSpec.Server.Debug.Println("Invalid bind packet.")
		return LDAPResultProtocolError
	}

	bindAuth := req.Children[2]
	bindSpec.BindAuth = bindAuth.Tag
	bindSpec.Server.Debug.Println("Bind Request Tag:", bindAuth.Tag, "Data:", bindAuth.Data.String())

	switch bindAuth.Tag {
	case LDAPBindAuthSimple:
		if len(req.Children) == 3 {
			fnNames := []string{}
			for k := range fns {
				fnNames = append(fnNames, k)
			}
			fn := routeFunc(bindSpec.BindDN, fnNames)
			resultCode, err := fns[fn].Bind(bindSpec, bindAuth.Data.String(), conn)
			if err != nil {
				bindSpec.Server.Debug.Printf("BindFn Error %s", err.Error())
				return LDAPResultOperationsError
			}
			return resultCode
		} else {
			bindSpec.Server.Debug.Println("Simple bind request has wrong # children.  len(req.Children) != 3")
			return LDAPResultInappropriateAuthentication
		}
	case LDAPBindAuthSASL:
		if ldapVersion != 3 {
			return LDAPResultInappropriateAuthentication
		}

		// TODO: Build SASL implementations

		//ber.PrintPacket(req) // DEBUG

		//packet, _ := ber.ReadPacket(conn)
		//ber.PrintPacket(packet)
		bindSpec.Server.Debug.Println("SASL authentication is not supported", bindAuth.Data.String(), "len(req.Children) =", len(req.Children))
		return LDAPResultInappropriateAuthentication
	}

	bindSpec.Server.Debug.Println("Unknown LDAP authentication method")
	return LDAPResultInappropriateAuthentication
}

func encodeBindResponse(messageID int64, ldapResultCode uint16) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))

	bindReponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ApplicationBindResponse, nil, "Bind Response")
	bindReponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(ldapResultCode), "resultCode: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	bindReponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "errorMessage: "))

	responsePacket.AppendChild(bindReponse)

	// ber.PrintPacket(responsePacket)
	return responsePacket
}
