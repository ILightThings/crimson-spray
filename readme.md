# Crimson-Spray
---

Crimson-Spray is a lockout aware password sprayer for active directory testing. The goal of this tool was allow password spraying without having lock out end user accounts. Most tools do allow throttling, but this tool aim to make locking out accounts less of an issue.

Safe Guard Features:
@@ -10,22 +7,22 @@ Safe Guard Features:
- Each user has their own thread. A single lockout will not prevent other user attempts from proceeding with their guess, nor will it effect the order passwords are guess.
- Once a password has been confirmed as working, attempts for that user will cease.

`crimson-spray -u ".\testcase\users.txt" -p ".\testcase\passwords.txt" -d "attack.local" -t "10.255.0.2" -a 10 -l 5 -r 15 -v 1`

This command will run 9 password attempts then wait 6 minutes before trying another 9 attempts. If the account is detected to be locked out, it will wait 16 minutes before trying more passwords. This will only show success messages. 

`--help` output
```
usage: crimson-spray [-h|--help] -u|--username-file "<value>"
                     -p|--password-file "<value>" -d|--domain "<value>"       
                     -t|--target "<value>" -a|--Lockout-Threshold <integer>   
                     -l|--Lockout-Reset <integer> -r|--Lockout-Timer <integer>
                     [--bypass-wait] [--no-stats] [-v|--verbose <integer>]    

                     (v.0.1.1) A lockout aware password sprayer for Active    
                     Directory. Please enter the raw net accounts /domain     
                     variables for best results. It is also advisable to use  
                     this against service accounts.

Arguments:

  -h  --help               Print help information
  -u  --username-file      (Required) File of users separated by newlines
  -p  --password-file      (Required) File of passwords seperated by newlines.
                           A good wordlist generator can be found at
                           https://weakpass.com/generate
  -d  --domain             (Required) Domain of user
  -t  --target             (Required) IP or Hostname of target to authenticate
                           against
  -a  --Lockout-Threshold  (Required) Number of passwords attempts before
                           lockout. Attempts will not exceed this amount - 1.
  -l  --Lockout-Reset      (Required) Duration of time in minutes for the
                           threshold timer to elapse. An addition minute is
                           added
  -r  --Lockout-Timer      (Required) Duration of time in minutes for an locked
                           out account to become unlocked. If account lockout
                           is detected, program will wait this time + 1
                           minute.

      --bypass-wait        Bypass initial lock threshold reset period
      --no-stats           Suppress stats banner. Default: false
  -v  --verbose            0 - No output (will disable prerun stats) | 1 -
                           Success Messages | 2 - Lockout , Pause , and Success
                           Messages | 3 - Attempts, Pause, Lockout and Success
                           Messages | 4 - Debug Messages. Default: 2

```



---
## Considerations before running
- Although the command `net accounts /domain` will show you the lockout policy in the current context, the Domain may have seperate policys for different user groups and you may end up locking out accounts. Default verbosity is set to show when lockouts occur.
- Ensure there is no duplicates in the usernames list. This will cause a lockout as they are run twice.
- **Don't** run `rockyou.txt` or any other giant wordlist. It will just increase the time considerably. This is a tool for weak password that could be easily guesses. Check out https://weakpass.com/generate for good password generation.
- At the moment, this tool does not limit how many users at once it can do. Try to limit your users list to only service accounts, high value targets, or hand picked users.
- Consider the password policy and don't include passwords that don't meet the required length or complexity. This might be set independantly for certain groups.

--- 
## Installation instructions

Install instructions:

`go get github.com/ILightThings/crimson-spray`

Linux:

`~/go/bin/crimson-spray`

Windows:

`%USERPATH%/go/bin/crimson-spray`

Alternatively, add the GOPATH/bin to your env:PATH variable.

### Todo:
- [ ] Add a pause and resume feature. 
- [ ] Add a lockout check before ever attempt (Will need working creds)
- [ ] Add LDAP as a protocol method
- [x] Add estimated timer completion
- [ ] Add Jitter option
- [x] Add a default flag to wait lockout threshold before beginning
- [ ] Add different attack modes
- [ ] Add an option for max concurrent users
- [x] Add a pre-Spray Stats display
- [ ] Add found_users.txt file for output
- [x] Verbose Levels
- [ ] Add a message for account password expiry
- [ ] Check for duplicates in passwordlist and username list
- [ ] Add Output to file
- [x] Trim whitespace
