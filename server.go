package ldap

import (
	"crypto/tls"
	//"crypto/x509"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/pschou/go-tease"
)

type Binder interface {
	Bind(bind BindSpec, bindSimplePw string, conn net.Conn) (uint16, error)
}
type Searcher interface {
	Search(bind BindSpec, req SearchRequest, conn net.Conn) (ServerSearchResult, error)
}
type Adder interface {
	Add(bind BindSpec, req AddRequest, conn net.Conn) (uint16, error)
}
type Modifier interface {
	Modify(bind BindSpec, req ModifyRequest, conn net.Conn) (uint16, error)
}
type Deleter interface {
	Delete(bind BindSpec, deleteDN string, conn net.Conn) (uint16, error)
}
type ModifyDNr interface {
	ModifyDN(bind BindSpec, req ModifyDNRequest, conn net.Conn) (uint16, error)
}
type Comparer interface {
	Compare(bind BindSpec, req CompareRequest, conn net.Conn) (uint16, error)
}
type Abandoner interface {
	Abandon(bind BindSpec, conn net.Conn) error
}
type Extender interface {
	Extended(bind BindSpec, req ExtendedRequest, conn net.Conn) (uint16, error)
}
type Unbinder interface {
	Unbind(bind BindSpec, conn net.Conn) (uint16, error)
}
type Closer interface {
	Close(bind BindSpec, conn net.Conn) error
}

// Assignable functions selected by BaseDN
type Server struct {
	TLSConfig      *tls.Config
	CryptoStartTLS bool // Only supported with LDAPv3
	CryptoNone     bool
	CryptoFullTLS  bool

	EnableV2 bool // Does not support authentication methods
	EnableV3 bool

	BindFns     map[string]Binder
	SearchFns   map[string]Searcher
	AddFns      map[string]Adder
	ModifyFns   map[string]Modifier
	DeleteFns   map[string]Deleter
	ModifyDNFns map[string]ModifyDNr
	CompareFns  map[string]Comparer
	AbandonFns  map[string]Abandoner
	ExtendedFns map[string]Extender
	UnbindFns   map[string]Unbinder
	CloseFns    map[string]Closer
	Quit        chan bool
	EnforceLDAP bool
	stats       *Stats
	statsMutex  sync.Mutex
	Debug       debugging
}

type BindSpec struct {
	// Connection methud used for connection (StartTLS, FullTLS, or Plain)
	Method string

	// Bind/bound Designated Name for query
	BindDN string

	// BindAuth TAG
	BindAuth ber.Tag

	// SASL Authentication method
	SASLAuth string

	// UserData, this is a handle which is definable by the user so as to
	// maintain a consistant privilage set after the bind is complete.
	UserData interface{}

	// TLS allows SSL servers and other software to record information about the
	// TLS connection on which the request was received. This field is not filled
	// in by ReadRequest.  The server in this package sets the field for
	// TLS-enabled connections before invoking a handler; otherwise it leaves the
	// field nil.
	TLS *tls.ConnectionState

	// RemoteAddr allows servers and other software to record the network address
	// that sent the request, usually for logging. This field is not filled in by
	// ReadRequest and has no defined format. The server in this package sets
	// RemoteAddr to an "IP:port" address before invoking a handler.
	RemoteAddr net.Addr

	// Server configuration
	Server *Server
}

type Stats struct {
	Conns    int
	Binds    int
	Unbinds  int
	Searches int
	server   *Server
}

type ServerSearchResult struct {
	Entries    []*Entry
	Referrals  []string
	Controls   []Control
	ResultCode uint16
}

// Create a new server and assign a default handler.  The default has the map
// assignment.  baseDN = "".
func NewServer() *Server {
	s := &Server{
		CryptoStartTLS: false,
		CryptoNone:     true,
		CryptoFullTLS:  false,
		EnableV2:       true,
		EnableV3:       true,
	}
	s.Quit = make(chan bool)

	d := defaultHandler{}
	s.BindFns = make(map[string]Binder)
	s.SearchFns = make(map[string]Searcher)
	s.AddFns = make(map[string]Adder)
	s.ModifyFns = make(map[string]Modifier)
	s.DeleteFns = make(map[string]Deleter)
	s.ModifyDNFns = make(map[string]ModifyDNr)
	s.CompareFns = make(map[string]Comparer)
	s.AbandonFns = make(map[string]Abandoner)
	s.ExtendedFns = make(map[string]Extender)
	s.UnbindFns = make(map[string]Unbinder)
	s.CloseFns = make(map[string]Closer)
	s.BindFunc("", d)
	s.SearchFunc("", d)
	s.AddFunc("", d)
	s.ModifyFunc("", d)
	s.DeleteFunc("", d)
	s.ModifyDNFunc("", d)
	s.CompareFunc("", d)
	s.AbandonFunc("", d)
	s.ExtendedFunc("", d)
	s.UnbindFunc("", d)
	s.CloseFunc("", d)
	s.stats = nil
	return s
}
func (server *Server) BindFunc(baseDN string, f Binder) {
	server.BindFns[baseDN] = f
}
func (server *Server) SearchFunc(baseDN string, f Searcher) {
	server.SearchFns[baseDN] = f
}
func (server *Server) AddFunc(baseDN string, f Adder) {
	server.AddFns[baseDN] = f
}
func (server *Server) ModifyFunc(baseDN string, f Modifier) {
	server.ModifyFns[baseDN] = f
}
func (server *Server) DeleteFunc(baseDN string, f Deleter) {
	server.DeleteFns[baseDN] = f
}
func (server *Server) ModifyDNFunc(baseDN string, f ModifyDNr) {
	server.ModifyDNFns[baseDN] = f
}
func (server *Server) CompareFunc(baseDN string, f Comparer) {
	server.CompareFns[baseDN] = f
}
func (server *Server) AbandonFunc(baseDN string, f Abandoner) {
	server.AbandonFns[baseDN] = f
}
func (server *Server) ExtendedFunc(baseDN string, f Extender) {
	server.ExtendedFns[baseDN] = f
}
func (server *Server) UnbindFunc(baseDN string, f Unbinder) {
	server.UnbindFns[baseDN] = f
}
func (server *Server) CloseFunc(baseDN string, f Closer) {
	server.CloseFns[baseDN] = f
}
func (server *Server) QuitChannel(quit chan bool) {
	server.Quit = quit
}

func (server *Server) SetStats(enable bool) {
	server.statsMutex.Lock()
	defer server.statsMutex.Unlock()
	if enable {
		server.stats = &Stats{server: server}
	} else {
		server.stats = nil
	}
}

func (server *Server) GetStats() Stats {
	server.statsMutex.Lock()
	defer server.statsMutex.Unlock()
	stats := server.stats
	stats.server = nil
	return *stats
}

func (server *Server) ListenAndServe(listenString string) error {
	var ln net.Listener
	var err error

	ln, err = net.Listen("tcp", listenString)
	if err != nil {
		return err
	}

	err = server.Serve(ln)
	if err != nil {
		return err
	}
	return nil
}

func (server *Server) Serve(ln net.Listener) error {
	newConn := make(chan net.Conn)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				if !strings.HasSuffix(err.Error(), "use of closed network connection") {
					server.Debug.Printf("Error accepting network connection: %s", err.Error())
				}
				break
			}
			newConn <- conn
		}
	}()

listener:
	for {
		select {
		case c := <-newConn:
			server.stats.countConns(1)
			go server.handleConnection(c)
		case <-server.Quit:
			ln.Close()
			break listener
		}
	}
	return nil
}

//
func (server *Server) handleConnection(rawConn net.Conn) {
	teaseConn := tease.NewServer(rawConn)
	var conn net.Conn
	bindSpec := BindSpec{
		RemoteAddr: rawConn.RemoteAddr(),
		Method:     "",
		Server:     server,
	}

	// Create a tease buffer and read in some bytes
	initDat := make([]byte, 10)
	_, err := teaseConn.Read(initDat)
	//server.Debug.Printf("tease % x\n", initDat) // DEBUG
	if err != nil {
		return
	}

	// If FullTLS is specified, test the first byte for valid data
	if server.CryptoFullTLS && initDat[0] == 0x16 {
		// We have a FullTLS, we'll go ahead and connect the pipe to a TLS reader
		teaseConn.Replay() // rewind to the beginning
		teaseConn.Pipe()   // connect pipe

		tlscon := tls.Server(teaseConn, server.TLSConfig)
		tlscon.Handshake()
		conn = tlscon

		bindSpec.Method = "FullTLS"
		TLS_State := tlscon.ConnectionState()
		bindSpec.TLS = &TLS_State
		server.Debug.Printf("  Using CryptoFullTLS %#v\n", teaseConn)
	}
	if bindSpec.Method == "" && server.CryptoStartTLS && initDat[0] == 0x30 {
		// If StartTLS is specified, test the first byte for valid data
		// Try StartTLS mode by reading in the first ber packet
		teaseConn.Replay()
		packet, err := ber.ReadPacket(teaseConn)
		if err == nil {
			// If Ber read was successful
			if len(packet.Children) == 2 && packet.Children[1].Tag == ApplicationExtendedRequest {
				if messageID, ok := packet.Children[0].Value.(int64); ok {
					server.Debug.Printf("StartTLS initiating")

					// Connect the connection through the connection teaser
					teaseConn.Pipe()

					// Encode a response packet
					responsePacket := encodeLDAPResponse(messageID, ApplicationExtendedResponse, LDAPResultSuccess,
						LDAPResultCodeMap[LDAPResultSuccess])

					if err = sendPacket(teaseConn, responsePacket); err != nil {
						server.Debug.Printf("StartTLS sendPacket error %s", err.Error())
						return
					}

					tlscon := tls.Server(teaseConn, server.TLSConfig)
					tlscon.Handshake()
					conn = tlscon

					bindSpec.Method = "StartTLS"
					TLS_State := tlscon.ConnectionState()
					bindSpec.TLS = &TLS_State
					server.Debug.Printf("  Using CryptoStartTLS %#v\n", teaseConn)
				}
			}
		}
	}
	if bindSpec.Method == "" && server.CryptoNone && initDat[0] == 0x30 {
		// Fall back to using basic none crypto
		teaseConn.Replay() // rewind to the beginning
		teaseConn.Pipe()   // connect pipe
		conn = teaseConn

		bindSpec.Method = "Plain"
		server.Debug.Printf("  Using CryptoNone %#v\n", teaseConn)
	}

	if bindSpec.Method == "" {
		return
	}

handler:
	for {
		// read incoming LDAP packet
		packet, err := ber.ReadPacket(conn)
		if err == io.EOF { // Client closed connection
			break
		} else if err != nil {
			server.Debug.Printf("handleConnection ber.ReadPacket ERROR: %s\n", err.Error())
			break
		}

		// sanity check this packet
		if len(packet.Children) < 2 {
			server.Debug.Println("ber read error, len(packet.Children) < 2")
			break
		}

		// check the message ID and ClassType
		messageID, ok := packet.Children[0].Value.(int64)
		if !ok {
			server.Debug.Println("malformed messageID", packet.Children[0])
			break
		}
		req := packet.Children[1]
		if req.ClassType != ber.ClassApplication {
			server.Debug.Println("req.ClassType != ber.ClassApplication")
			break
		}
		// handle controls if present
		controls := []Control{}
		if len(packet.Children) > 2 {
			for _, child := range packet.Children[2].Children {
				control, err := DecodeControl(child)
				if err != nil {
					server.Debug.Printf("malformed control error %s", err.Error())
					return
				}
				controls = append(controls, control)
			}
		}

		//server.Debug.Printf("DEBUG: handling operation: %s [%d]", ApplicationMap[req.Tag], req.Tag)
		//ber.PrintPacket(packet) // DEBUG

		// dispatch the LDAP operation
		switch req.Tag { // ldap op code
		default:
			responsePacket := encodeLDAPResponse(messageID, ApplicationAddResponse, LDAPResultOperationsError, "Unsupported operation: add")
			if err = sendPacket(conn, responsePacket); err != nil {
				server.Debug.Printf("sendPacket error %s", err.Error())
			}
			server.Debug.Printf("Unhandled operation: %s [%d]", ApplicationMap[uint8(req.Tag)], req.Tag)
			break handler

		case ApplicationBindRequest:
			server.stats.countBinds(1)
			ldapResultCode := HandleBindRequest(req, bindSpec, server.BindFns, conn)
			if ldapResultCode == LDAPResultSuccess {
				bindSpec.BindDN, ok = req.Children[1].Value.(string)
				if !ok {
					server.Debug.Printf("Malformed Bind DN")
					break handler
				}
			}
			server.Debug.Println("encode bind packet")
			responsePacket := encodeBindResponse(messageID, ldapResultCode)
			//server.Debug.Println("responding")       //DEBUG
			//ber.PrintPacket(responsePacket) //DEBUG
			if err = sendPacket(conn, responsePacket); err != nil {
				server.Debug.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationSearchRequest:
			server.stats.countSearches(1)
			server.Debug.Printf("handleSearchRequest %#v", bindSpec)
			if err := HandleSearchRequest(req, bindSpec, &controls, messageID, conn); err != nil {
				// TODO: make this more testable/better err handling - stop using log, stop using breaks?
				server.Debug.Printf("handleSearchRequest error %s", err.Error())
				e := err.(*Error)
				if err = sendPacket(conn, encodeSearchDone(messageID, e.ResultCode)); err != nil {
					server.Debug.Printf("sendPacket error %s", err.Error())
					break handler
				}
				break handler
			} else {
				if err = sendPacket(conn, encodeSearchDone(messageID, LDAPResultSuccess)); err != nil {
					server.Debug.Printf("sendPacket error %s", err.Error())
					break handler
				}
			}
		case ApplicationUnbindRequest:
			server.stats.countUnbinds(1)
			break handler // simply disconnect
		case ApplicationExtendedRequest:
			ldapResultCode := HandleExtendedRequest(req, bindSpec, server.ExtendedFns, conn)
			responsePacket := encodeLDAPResponse(messageID, ApplicationExtendedResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
			if err = sendPacket(conn, responsePacket); err != nil {
				server.Debug.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationAbandonRequest:
			HandleAbandonRequest(req, bindSpec, server.AbandonFns, conn)
			break handler

		case ApplicationAddRequest:
			ldapResultCode := HandleAddRequest(req, bindSpec, server.AddFns, conn)
			responsePacket := encodeLDAPResponse(messageID, ApplicationAddResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
			if err = sendPacket(conn, responsePacket); err != nil {
				server.Debug.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationModifyRequest:
			ldapResultCode := HandleModifyRequest(req, bindSpec, server.ModifyFns, conn)
			responsePacket := encodeLDAPResponse(messageID, ApplicationModifyResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
			if err = sendPacket(conn, responsePacket); err != nil {
				server.Debug.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationDelRequest:
			ldapResultCode := HandleDeleteRequest(req, bindSpec, server.DeleteFns, conn)
			responsePacket := encodeLDAPResponse(messageID, ApplicationDelResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
			if err = sendPacket(conn, responsePacket); err != nil {
				server.Debug.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationModifyDNRequest:
			ldapResultCode := HandleModifyDNRequest(req, bindSpec, server.ModifyDNFns, conn)
			responsePacket := encodeLDAPResponse(messageID, ApplicationModifyDNResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
			if err = sendPacket(conn, responsePacket); err != nil {
				server.Debug.Printf("sendPacket error %s", err.Error())
				break handler
			}
		case ApplicationCompareRequest:
			ldapResultCode := HandleCompareRequest(req, bindSpec, server.CompareFns, conn)
			responsePacket := encodeLDAPResponse(messageID, ApplicationCompareResponse, ldapResultCode, LDAPResultCodeMap[ldapResultCode])
			if err = sendPacket(conn, responsePacket); err != nil {
				server.Debug.Printf("sendPacket error %s", err.Error())
				break handler
			}
		}
	}

	for _, c := range server.CloseFns {
		c.Close(bindSpec, conn)
	}

}

//
func sendPacket(conn net.Conn, packet *ber.Packet) error {
	_, err := conn.Write(packet.Bytes())
	if err != nil {
		log.Printf("Error Sending Message: %s", err.Error())
		return err
	}
	return nil
}

//
func routeFunc(dn string, funcNames []string) string {
	bestPick := ""
	for _, fn := range funcNames {
		if strings.HasSuffix(dn, fn) {
			l := len(strings.Split(bestPick, ","))
			if bestPick == "" {
				l = 0
			}
			if len(strings.Split(fn, ",")) > l {
				bestPick = fn
			}
		}
	}
	return bestPick
}

//
func encodeLDAPResponse(messageID int64, responseType ber.Tag, ldapResultCode uint16, message string) *ber.Packet {
	responsePacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Response")
	responsePacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageID, "Message ID"))
	reponse := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ber.Tag(responseType), nil, ApplicationMap[uint8(responseType)])
	reponse.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, uint64(ldapResultCode), "resultCode: "))
	reponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "matchedDN: "))
	reponse.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, message, "errorMessage: "))
	responsePacket.AppendChild(reponse)
	return responsePacket
}

//
type defaultHandler struct {
}

func (h defaultHandler) Bind(bind BindSpec, bindSimplePw string, conn net.Conn) (uint16, error) {
	return LDAPResultInvalidCredentials, nil
}
func (h defaultHandler) Search(bind BindSpec, req SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	return ServerSearchResult{make([]*Entry, 0), []string{}, []Control{}, LDAPResultSuccess}, nil
}
func (h defaultHandler) Add(bind BindSpec, req AddRequest, conn net.Conn) (uint16, error) {
	return LDAPResultInsufficientAccessRights, nil
}
func (h defaultHandler) Modify(bind BindSpec, req ModifyRequest, conn net.Conn) (uint16, error) {
	return LDAPResultInsufficientAccessRights, nil
}
func (h defaultHandler) Delete(bind BindSpec, deleteDN string, conn net.Conn) (uint16, error) {
	return LDAPResultInsufficientAccessRights, nil
}
func (h defaultHandler) ModifyDN(bind BindSpec, req ModifyDNRequest, conn net.Conn) (uint16, error) {
	return LDAPResultInsufficientAccessRights, nil
}
func (h defaultHandler) Compare(bind BindSpec, req CompareRequest, conn net.Conn) (uint16, error) {
	return LDAPResultInsufficientAccessRights, nil
}
func (h defaultHandler) Abandon(bind BindSpec, conn net.Conn) error {
	return nil
}
func (h defaultHandler) Extended(bind BindSpec, req ExtendedRequest, conn net.Conn) (uint16, error) {
	return LDAPResultProtocolError, nil
}
func (h defaultHandler) Unbind(bind BindSpec, conn net.Conn) (uint16, error) {
	return LDAPResultSuccess, nil
}
func (h defaultHandler) Close(bind BindSpec, conn net.Conn) error {
	conn.Close()
	return nil
}

//
func (stats *Stats) countConns(delta int) {
	if stats != nil {
		stats.server.statsMutex.Lock()
		stats.Conns += delta
		stats.server.statsMutex.Unlock()
	}
}
func (stats *Stats) countBinds(delta int) {
	if stats != nil {
		stats.server.statsMutex.Lock()
		stats.Binds += delta
		stats.server.statsMutex.Unlock()
	}
}
func (stats *Stats) countUnbinds(delta int) {
	if stats != nil {
		stats.server.statsMutex.Lock()
		stats.Unbinds += delta
		stats.server.statsMutex.Unlock()
	}
}
func (stats *Stats) countSearches(delta int) {
	if stats != nil {
		stats.server.statsMutex.Lock()
		stats.Searches += delta
		stats.server.statsMutex.Unlock()
	}
}

//
