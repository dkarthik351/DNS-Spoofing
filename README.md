# DNS-Spoofing

**DNS** stands for **D**omain **N**ame **S**ystem and the main purpose of DNS is to translate Domain Names to IP addresses. **DNS spoofing** refers to an attack that modifies the DNS records returned to the querier. This can be achieved with different techniques such as DNS Hijacking or DNS cache poisoning. The purpose of the attack is to redirect users to malicious websites instead of legitimate website.



This repository consists of DNS spoofing application which does some type of Man-In-The-Middle attack which intercepts the DNS queries in the network and sends out  spoofed DNS responses with user-defined IP addresses. The same application is implemented in two programmig languages, *C* and *Python*, and they work independantly. Choose one implementation that suits your requirement.


**Note:** 
- To utilize this application in real-world, the application should have access to sniff the packets in the network. Otherwise [ARP spoofing](https://en.wikipedia.org/wiki/ARP_spoofing) is required before utilizing this application. 

- Additional DNS Hijacking techniques to explore includes **Local DNS Hijack** using malware/Trojan on user's computer, **Router DNS Hijack** in which the attacker gets hold of Router and modifies the DNS settings. 
