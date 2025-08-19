# 1. Initial scan

```
└─# arp-scan -l | grep PCS
192.168.31.8    08:00:27:c0:05:39       PCS Systemtechnik GmbH
└─# IP=192.168.31.8
└─# nmap -sV -sC -A $IP -Pn
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-10 12:58 CST
Nmap scan report for 13max (192.168.31.8)
Host is up (0.0019s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     pyftpdlib 2.0.1
| ftp-syst:
|   STAT:
| FTP server status:
|  Connected to: 192.168.31.8:21
|  Waiting for username.
|  TYPE: ASCII; STRUcture: File; MODE: Stream
|  Data connection closed.
|_End of status.
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
| ssh-hostkey:
|   3072 f6:a3:b6:78:c4:62:af:44:bb:1a:a0:0c:08:6b:98:f7 (RSA)
|   256 bb:e8:a2:31:d4:05:a9:c9:31:ff:62:f6:32:84:21:9d (ECDSA)
|_  256 3b:ae:34:64:4f:a5:75:b9:4a:b9:81:f9:89:76:99:eb (ED25519)
80/tcp open  http    Apache httpd 2.4.62 ((Debian))
|_http-title: iCloud Vault Access
|_http-server-header: Apache/2.4.62 (Debian)
MAC Address: 08:00:27:C0:05:39 (PCS Systemtechnik/Oracle VirtualBox virtual NIC)
```