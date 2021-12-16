package protocol

import (
	"testing"
)


func TestLdapConnect(t *testing.T) {
	_,err := LdapConnect("10.255.0.2", "guy", "Spring2021!")
	if err != nil {
		t.Fatalf("Could not connect. Ldap connection failed. %s",err)
	}
}

func TestLdapQuery(t *testing.T) {
	conn,_ := LdapConnect(
		"10.255.0.2",
		"guy",
		"Spring2021!",
		)
 results, err := LdapQuery(conn,"(&(objectSid=S-1-5-21-3067534155-3217308170-1223593864-500))","attack.local") //Administarator SID. Should never change.
 if err != nil || len(results.Entries) == 0 {
 	t.Errorf("Ldap Query failed. %s",err)
 }

}

func TestLdapCheckLockout(t *testing.T) {
	_,err := LdapCheckLockout(
		"guy@attack.local",
		"10.255.0.2",
		"guy",
		"Spring2021!",
		"attack.local")
	if err != nil {
		t.Errorf("LDAP Lockout Query Failed. %s",err)
	}

}


