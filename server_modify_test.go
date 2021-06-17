package ldap

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"
	"time"
)

//
func TestAdd(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	closed := make(chan bool)
	listenString := randomHostPort()
	ldapURL := fmt.Sprintf("ldap://%s", listenString)

	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", modifyTestHandler{})
		s.AddFunc("", modifyTestHandler{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
		closed <- true
	}()
	go func() {
		cmd := exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add.ldif")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd failed: %v", string(out))
		}
		cmd = exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_add: Insufficient access") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		if strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapadd command timed out")
	}
	quit <- true
	<-closed
}

//
func TestDelete(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	closed := make(chan bool)
	listenString := randomHostPort()
	ldapURL := fmt.Sprintf("ldap://%s", listenString)

	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", modifyTestHandler{})
		s.DeleteFunc("", modifyTestHandler{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
		closed <- true
	}()
	go func() {
		cmd := exec.Command("ldapdelete", "-v", "-H", ldapURL, "-x", "cn=Delete Me,dc=example,dc=com")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "Delete Result: Success (0)") || !strings.Contains(string(out), "Additional info: Success") {
			t.Errorf("ldapdelete failed: %v", string(out))
		}
		cmd = exec.Command("ldapdelete", "-v", "-H", ldapURL, "-x", "cn=Bob,dc=example,dc=com")
		out, _ = cmd.CombinedOutput()
		if strings.Contains(string(out), "Success") || !strings.Contains(string(out), "ldap_delete: Insufficient access") {
			t.Errorf("ldapdelete should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapdelete command timed out")
	}
	quit <- true
	<-closed
}

func TestModify(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	closed := make(chan bool)
	listenString := randomHostPort()
	ldapURL := fmt.Sprintf("ldap://%s", listenString)

	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", modifyTestHandler{})
		s.ModifyFunc("", modifyTestHandler{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
		closed <- true
	}()
	time.Sleep(timeout)
	go func() {
		cmd := exec.Command("ldapmodify", "-v", "-H", ldapURL, "-x", "-f", "tests/modify.ldif")
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapmodify failed: %v", string(out))
		}
		cmd = exec.Command("ldapmodify", "-v", "-H", ldapURL, "-x", "-f", "tests/modify2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_modify: Insufficient access") || strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapmodify should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapadd command timed out")
	}
	quit <- true
	<-closed
}

func TestModifyDN(t *testing.T) {
	quit := make(chan bool)
	done := make(chan bool)
	closed := make(chan bool)
	listenString := randomHostPort()
	ldapURL := fmt.Sprintf("ldap://%s", listenString)

	go func() {
		s := NewServer()
		s.QuitChannel(quit)
		s.BindFunc("", modifyTestHandler{})
		s.AddFunc("", modifyTestHandler{})
		if err := s.ListenAndServe(listenString); err != nil {
			t.Errorf("s.ListenAndServe failed: %s", err.Error())
		}
		closed <- true
	}()
	go func() {
		cmd := exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add.ldif")
		//ldapmodrdn -H ldap://localhost:3389 -x "uid=babs,dc=example,dc=com" "uid=babsy,dc=example,dc=com"
		out, _ := cmd.CombinedOutput()
		if !strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd failed: %v", string(out))
		}
		cmd = exec.Command("ldapadd", "-v", "-H", ldapURL, "-x", "-f", "tests/add2.ldif")
		out, _ = cmd.CombinedOutput()
		if !strings.Contains(string(out), "ldap_add: Insufficient access") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		if strings.Contains(string(out), "modify complete") {
			t.Errorf("ldapadd should have failed: %v", string(out))
		}
		done <- true
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		t.Errorf("ldapadd command timed out")
	}
	quit <- true
	<-closed
}

//
type modifyTestHandler struct {
}

func (h modifyTestHandler) Bind(bindSpec BindSpec, bindSimplePw string, conn net.Conn) (uint16, error) {
	if bindSpec.BindDN == "" && bindSimplePw == "" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInvalidCredentials, nil
}
func (h modifyTestHandler) Add(bindSpec BindSpec, req AddRequest, conn net.Conn) (uint16, error) {
	// only succeed on expected contents of add.ldif:
	if len(req.Attributes) == 5 && req.DN == "cn=Barbara Jensen,dc=example,dc=com" &&
		req.Attributes[2].Type == "sn" && len(req.Attributes[2].Vals) == 1 &&
		req.Attributes[2].Vals[0] == "Jensen" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInsufficientAccessRights, nil
}
func (h modifyTestHandler) Delete(bindSpec BindSpec, deleteDN string, conn net.Conn) (uint16, error) {
	// only succeed on expected deleteDN
	if deleteDN == "cn=Delete Me,dc=example,dc=com" {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInsufficientAccessRights, nil
}
func (h modifyTestHandler) Modify(bindSpec BindSpec, req ModifyRequest, conn net.Conn) (uint16, error) {
	// only succeed on expected contents of modify.ldif:
	if req.DN == "cn=testy,dc=example,dc=com" && len(req.AddAttributes) == 1 &&
		len(req.DeleteAttributes) == 3 && len(req.ReplaceAttributes) == 2 &&
		req.DeleteAttributes[2].Type == "details" && len(req.DeleteAttributes[2].Vals) == 0 {
		return LDAPResultSuccess, nil
	}
	return LDAPResultInsufficientAccessRights, nil
}
func (h modifyTestHandler) ModifyDN(bindSpec BindSpec, req ModifyDNRequest, conn net.Conn) (uint16, error) {
	return LDAPResultInsufficientAccessRights, nil
}
