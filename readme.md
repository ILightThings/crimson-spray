Placeholder text.

Use -h for usage.

`go run main.go -u ".\testcase\users.txt" -p ".\testcase\passwords.txt" -d "attack.local" -t "10.255.0.2" -a 10 -l 5 -r 5`


```
usage: Crimson Spary [-h|--help] -u|--username-file "<value>"
                     -p|--password-file "<value>" -d|--domain "<value>"
                     -t|--target "<value>" -a|--Lockout-Threshold <integer>
                     -l|--Lockout-Reset <integer> -r|--Lockout-Timer <integer>
                     [--bypass-wait] [--no-stats] [-v|--verbose]

                     A lockout aware password sprayer for Internal network
                     security assessments.

Arguments:

  -h  --help               Print help information
  -u  --username-file      File of users separated by newlines
  -p  --password-file      File of passwords seperated by newlines. A good
                           wordlist generator can be found at
                           https://weakpass.com/generate
  -d  --domain
  -t  --target             IP or Hostname of target to authenticate against.
  -a  --Lockout-Threshold  Number of passwords attempts before lockout.
                           Attempts will not exceed this amount - 1.
  -l  --Lockout-Reset      Duration of time in minutes for the threshold timer
                           to elapse. An addition minute is added.
  -r  --Lockout-Timer      Duration of time in minutes for an locked out
                           account to become unlocked. If account lockout is
                           detected, program will wait this time + 1 minute.
      --bypass-wait        Bypass initial lock threshold reset period
      --no-stats           Suppress stats banner. Default: false
  -v  --verbose            Print Debug. Default: false

```




Todo:
- [ ] Add a pause and resume feature. 
- [ ] Add a lockout check before ever attempt (Will need working creds)
- [ ] Add LDAP as a protocol method
- [ ] Add estimated timer completion
- [ ] Add Jitter option
- [x] Add a default flag to wait lockout threshold before beginning
- [ ] Add different attack modes
- [ ] Add an option for max concurrent users
- [x] Add a pre-Spray Stats display

