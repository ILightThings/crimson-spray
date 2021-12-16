package protocol

import (
	"fmt"
	"gopkg.in/ldap.v2"
	"strings"
)


func LdapConnect(dcHost string,authUsername string, authPassword string) (*ldap.Conn,error){
	ldapDCAdress := fmt.Sprintf("%s:389",dcHost)
	ldapConnection, err := ldap.Dial("tcp",ldapDCAdress)
	if err !=nil {
		return ldapConnection, err
	}
	err = ldapConnection.Bind(authUsername,authPassword)
	if err != nil{
		return ldapConnection,err
	}
	return ldapConnection,nil
}

func LdapQuery(connection *ldap.Conn,ldapQueryString string,domainRawString string) (*ldap.SearchResult,error){
ldapConnection := connection
domainComponentString := domainComponentStringConvert(domainRawString)
	resultQ := ldap.NewSearchRequest(domainComponentString,
	ldap.ScopeWholeSubtree,
	ldap.NeverDerefAliases,
	2,
	0,
	false,
	ldapQueryString,
	[]string{"*"},
	nil,
	)
	result,err := ldapConnection.Search(resultQ)
	return result,err

}

func LdapCheckLockout(userToCheck string,dcHost string,authUsername string,authPassword string,domainRawString string)(bool,error){
	connection,err := LdapConnect(dcHost,authUsername,authPassword)
	if err != nil {
		return true,err
	}
	userPrincipalNameString := fmt.Sprintf("%s@%s",userToCheck,domainRawString)
	ldapLockoutQuery := fmt.Sprintf("(&(userPrincipalName=%s))",userPrincipalNameString)
	_,errQ := LdapQuery(connection,ldapLockoutQuery,domainRawString)
	if errQ != nil {
		return true,errQ
	}
	return true,nil
}


func domainComponentStringConvert(domain string)string {
	domainComp := strings.Split(domain,".")
	var domainString []string
	for _,y := range domainComp {
		domainString = append(domainString,fmt.Sprintf("dc=%s",y))
	}

	domainComponent := strings.Join(domainString,",")
	return domainComponent
}


