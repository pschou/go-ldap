package ldap

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func randomHostPort() string {
	return fmt.Sprintf("127.0.0.1:%d", rand.Intn(30000)+30000)
}

//var ldapURL = "ldap://" + listenString
var timeout = 200 * time.Millisecond
var serverBaseDN = "o=testers,c=test"

/////////////////////////
func TestBindAnonOK(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	closed := make(chan bool)
	listenString := randomHostPort()
	ldapURL := fmt.Sprintf("ldap://%s", listenString)

	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindAnonOK{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
		closed <- true
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
	<-closed
}

/////////////////////////
func TestBindAnonFail(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	closed := make(chan bool)
	listenString := randomHostPort()
	ldapURL := fmt.Sprintf("ldap://%s", listenString)

	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
		closed <- true
	}()

	time.Sleep(timeout)
	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	time.Sleep(timeout)
	quit <- true
	<-closed
}

/////////////////////////
func TestBindSimpleOK(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	closed := make(chan bool)
	listenString := randomHostPort()
	ldapURL := fmt.Sprintf("ldap://%s", listenString)

	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
		closed <- true
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}

	quit <- true
	<-closed
}

/////////////////////////
func TestBindStartTLS(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	closed := make(chan bool)
	listenString := randomHostPort()
	ldapURL := fmt.Sprintf("ldap://%s", listenString)

	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindSimple{})
		s.TLSConfig = tlsConfig
		s.CryptoStartTLS = true
		s.CryptoFullTLS = false
		s.CryptoNone = false
		//s.Debug = true
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
		closed <- true
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-Z", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout * 4):
		t.Errorf("ldapsearch command timed out")
	}

	quit <- true
	<-closed
}

/////////////////////////
func TestBindSimpleFailBadPw(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	closed := make(chan bool)
	listenString := randomHostPort()
	ldapURL := fmt.Sprintf("ldap://%s", listenString)

	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
		closed <- true
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testy,"+serverBaseDN, "-w", "BADPassword")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Invalid credentials (49)") {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
	<-closed
}

/////////////////////////
func TestBindSimpleFailBadDn(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	closed := make(chan bool)
	listenString := randomHostPort()
	ldapURL := fmt.Sprintf("ldap://%s", listenString)

	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindSimple{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
		closed <- true
	}()

	serverBaseDN := "o=testers,c=test"

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x",
			"-b", serverBaseDN, "-D", "cn=testoy,"+serverBaseDN, "-w", "iLike2test")
		out, _ := cmd.CombinedOutput()
		if string(out) != "ldap_bind: Invalid credentials (49)\n" {
			t.Errorf("ldapsearch succeeded - should have failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
	<-closed
}

func init() {
	os.Setenv("LDAPTLS_CACERT", fmt.Sprintf("tests%cca_cert_DONOTUSE.pem", os.PathSeparator))

	cert, err := tls.LoadX509KeyPair(
		fmt.Sprintf("tests%ccert_DONOTUSE.pem", os.PathSeparator),
		fmt.Sprintf("tests%ckey_DONOTUSE.pem", os.PathSeparator),
	)
	//fmt.Println("tests/key_DONOTUSE.pem", cert)
	if err != nil {
		log.Fatalf("tls.LoadX509KeyPair failed: %s", err.Error())
	}
	// Get the SystemCertPool, continue with an empty pool on error
	//rootCAs, _ := x509.SystemCertPool()
	//if rootCAs == nil {
	rootCAs := x509.NewCertPool()
	//}
	// Read in the cert file
	certs, err := ioutil.ReadFile(
		fmt.Sprintf("tests%cca_cert_DONOTUSE.pem", os.PathSeparator),
	)
	if err != nil {
		log.Fatalf("ReadFile for CA failed: %s", err.Error())
	}
	// Append our cert to the CA pool
	if ok := rootCAs.AppendCertsFromPEM(certs); !ok {
		log.Fatalf("No CA certs appended: %s", err.Error())
	}
	tlsConfig = &tls.Config{
		Certificates:       []tls.Certificate{cert},
		ServerName:         "localhost",
		InsecureSkipVerify: true,
		//ClientAuth: tls.RequireAndVerifyClientCert,
		//ClientAuth: tls.RequireAnyClientCert,
		ClientAuth: tls.NoClientCert,
		RootCAs:    rootCAs,
		ClientCAs:  rootCAs,
	}

}

var tlsConfig *tls.Config

/////////////////////////
func TestBindSSL(t *testing.T) {
	listenString := randomHostPort()
	ldapURLSSL := fmt.Sprintf("ldaps://%s", listenString)

	//longerTimeout := 600 * time.Millisecond
	quit := make(chan bool)
	done := make(chan bool)
	go func() {
		server := NewServer()
		server.QuitChannel(quit)
		server.BindFunc("", bindAnonOK{})
		server.TLSConfig = tlsConfig
		server.CryptoNone = false
		server.CryptoFullTLS = true
		server.CryptoStartTLS = false
		if err := server.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
	}()

	go func() {
		time.Sleep(timeout)
		cmd := exec.Command("ldapsearch", "-H", ldapURLSSL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout * 4):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
}

/////////////////////////
func TestBindPanic(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	closed := make(chan bool)
	listenString := randomHostPort()
	ldapURL := fmt.Sprintf("ldap://%s", listenString)

	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", bindPanic{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
		closed <- true
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_bind: Operations error") {
			t.Errorf("ldapsearch should have returned operations error due to panic: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}
	quit <- true
	<-closed
}

/////////////////////////
type testStatsWriter struct {
	buffer *bytes.Buffer
}

func (tsw testStatsWriter) Write(buf []byte) (int, error) {
	tsw.buffer.Write(buf)
	return len(buf), nil
}

func TestSearchStats(t *testing.T) {
	w := testStatsWriter{&bytes.Buffer{}}
	log.SetOutput(w)

	quit := make(chan bool)
	done := make(chan bool)
	closed := make(chan bool)
	listenString := randomHostPort()
	ldapURL := fmt.Sprintf("ldap://%s", listenString)

	s := NewServer()

	go func() {
		s.QuitChannel(quit)
		s.SearchFunc("", searchSimple{})
		s.BindFunc("", bindAnonOK{})
		s.SetStats(true)
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
		closed <- true
	}()

	go func() {
		cmd := exec.Command("ldapsearch", "-H", ldapURL, "-x", "-b", "o=testers,c=test")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "result: 0 Success") {
			t.Errorf("ldapsearch failed: %v", string(out))
		}
		done <- true
	}()

	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapsearch command timed out")
	}

	stats := s.GetStats()
	log.Println(stats)
	if stats.Conns != 1 || stats.Binds != 1 {
		t.Errorf("Stats data missing or incorrect: %v", w.buffer.String())
	}
	quit <- true
	<-closed
}

/////////////////////////
type bindAnonOK struct {
}

func (b bindAnonOK) Bind(bindSpec BindSpec, bindSimplePw string, conn net.Conn) (uint16, error) {
	if bindSpec.BindDN == "" && bindSimplePw == "" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindSimple struct {
}

func (b bindSimple) Bind(bindSpec BindSpec, bindSimplePw string, conn net.Conn) (uint16, error) {
	if bindSpec.BindDN == "cn=testy,o=testers,c=test" && bindSimplePw == "iLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindSimple2 struct {
}

func (b bindSimple2) Bind(bindSpec BindSpec, bindSimplePw string, conn net.Conn) (uint16, error) {
	if bindSpec.BindDN == "cn=testy,o=testers,c=testz" && bindSimplePw == "ZLike2test" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}

type bindPanic struct {
}

func (b bindPanic) Bind(bindSpec BindSpec, bindSimplePw string, conn net.Conn) (uint16, error) {
	if 1 == 2-1 {
		panic("bind panic test")
	}
	return LDAPResultInvalidCredentials, nil
}

type searchSimple struct {
}

func (s searchSimple) Search(bindSpec BindSpec, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		&Entry{"cn=ned,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{Name: "cn", Values: []string{"ned"}},
			&EntryAttribute{Name: "o", Values: []string{"ate"}},
			&EntryAttribute{Name: "uidNumber", Values: []string{"5000"}},
			&EntryAttribute{Name: "accountstatus", Values: []string{"active"}},
			&EntryAttribute{Name: "uid", Values: []string{"ned"}},
			&EntryAttribute{Name: "description", Values: []string{"ned via sa"}},
			&EntryAttribute{Name: "objectclass", Values: []string{"posixaccount"}},
		}},
		&Entry{"cn=trent,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{Name: "cn", Values: []string{"trent"}},
			&EntryAttribute{Name: "o", Values: []string{"ate"}},
			&EntryAttribute{Name: "uidNumber", Values: []string{"5005"}},
			&EntryAttribute{Name: "accountstatus", Values: []string{"active"}},
			&EntryAttribute{Name: "uid", Values: []string{"trent"}},
			&EntryAttribute{Name: "description", Values: []string{"trent via sa"}},
			&EntryAttribute{Name: "objectclass", Values: []string{"posixaccount"}},
		}},
		&Entry{"cn=randy,o=testers,c=test", []*EntryAttribute{
			&EntryAttribute{Name: "cn", Values: []string{"randy"}},
			&EntryAttribute{Name: "o", Values: []string{"ate"}},
			&EntryAttribute{Name: "uidNumber", Values: []string{"5555"}},
			&EntryAttribute{Name: "accountstatus", Values: []string{"active"}},
			&EntryAttribute{Name: "uid", Values: []string{"randy"}},
			&EntryAttribute{Name: "objectclass", Values: []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchSimple2 struct {
}

func (s searchSimple2) Search(bindSpec BindSpec, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{
		&Entry{"cn=hamburger,o=testers,c=testz", []*EntryAttribute{
			&EntryAttribute{Name: "cn", Values: []string{"hamburger"}},
			&EntryAttribute{Name: "o", Values: []string{"testers"}},
			&EntryAttribute{Name: "uidNumber", Values: []string{"5000"}},
			&EntryAttribute{Name: "accountstatus", Values: []string{"active"}},
			&EntryAttribute{Name: "uid", Values: []string{"hamburger"}},
			&EntryAttribute{Name: "objectclass", Values: []string{"posixaccount"}},
		}},
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchPanic struct {
}

func (s searchPanic) Search(bindSpec BindSpec, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{}
	if 1 == 2-1 {
		panic("panic in search")
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}

type searchControls struct {
}

func (s searchControls) Search(bindSpec BindSpec, searchReq SearchRequest, conn net.Conn) (ServerSearchResult, error) {
	entries := []*Entry{}
	if len(searchReq.Controls) == 1 && searchReq.Controls[0].GetControlType() == "1.2.3.4.5" {
		newEntry := &Entry{"cn=hamburger,o=testers,c=testz", []*EntryAttribute{
			&EntryAttribute{Name: "cn", Values: []string{"hamburger"}},
			&EntryAttribute{Name: "o", Values: []string{"testers"}},
			&EntryAttribute{Name: "uidNumber", Values: []string{"5000"}},
			&EntryAttribute{Name: "accountstatus", Values: []string{"active"}},
			&EntryAttribute{Name: "uid", Values: []string{"hamburger"}},
			&EntryAttribute{Name: "objectclass", Values: []string{"posixaccount"}},
		}}
		entries = append(entries, newEntry)
	}
	return ServerSearchResult{entries, []string{}, []Control{}, LDAPResultSuccess}, nil
}
