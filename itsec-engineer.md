---
layout: page
title: "Security Engineer"
permalink: /securityengineer
---

# Engineering

Tell us about some controls that are commonly used to secure a company.


--------------
Check some vocab knowledge:
```
asset - what you are trying to protect
threat - something that can affect the CIA triad
vulnerability - a weakness or flaw in a security program that, if exploited, threatens CIA triad
risk - a potential for damage to the CIA triad as a result of a threat
exploit - program/code designed to take advantage of a vulnerability

Severity = Asset Priority * Threat Impact
Risk  = Probability *  Severity
```

How does Anti-Malware work?


Describe Dynamic Analysis vs. Static.


What is the CIA Triad? Explain.
```
Confidentiality | Integrity | Availability
```

What is AAA? Explain.
```
Authentication | Authorization | Accounting
```

## Controlls
```
Tell us about some controls that are commonly used to secure a company.
```
Firewall|Anti-Virus|EDR|NDR|Proxy|ESG|IDS/IPS|secret managers|SIEM|App Whitelisting|Script Control|UBA/UEBA|CASB|Vulnerability Scanners|MFA/2FA|SOAR|etc


What is the difference been a SIEM and IDS, and IPS?

```
SIEM - combines security information management and security event management - collects and aggregates events for alerting, analysis/investigation
NIDS - event generation - uses signatures, pattern matching, reputation scoring, or anomaly detection to generate security events in network traffic
HIDS - event generation - uses signatures, pattern matching, reputation scoring, or anomaly detection to generate security events on a host
```

What is EDR?
```
Endpoint Detection and Response (aka endpoint threat detection and response) - endpoint security solution that logs and monitors devices to detect and investigate cyber intrusions
```

What are some common ways the Cyber Industry uses machine learning?
```
open-ended
```

What are some XXS Countermeasures
```
Encoding the output
Applying filters at the point where input is received
Using appropriate response headers
Enabling content security policy
Escaping untrusted characters
```

## Network


What are the OSI layers?
```
App
Presentation
Session
Transport
Network
Data Link
Physical
```

What's the difference between TCP and UDP?
```
TCP - creates sessions, slower but reliable (unicast)
UDP - fast but not guaranteed, shout (unicast, multicast, broadcast)
```

What steps are involved in TCP handshake setup?
```
SYN
SYN-ACK
ACK
Congrats. You're established.
```

What are the TCP header flags? <br>
Do you know what they do?
```
SYN
URG
ACK
PSH
RST
FIN
```


What is the difference between droping traffic and denying / rejecting traffic on a firewall?

```
deny - will send an ICMP type 3 (destination unreachable) response
drop - no notification of denial / silently stops traffic
```

What is the difference between IDS and IPS?

```
IDS - detects security events
IPS - has the capability to block security events
```
How would you defend our network from that IP if there was an attack from a specific IP address? What about if those attacks were comming from a whole network?
```
Block the IP addresses
CIDR / ASN
```

What is SNMP?
  At what layer does this protocol exist `network.`
```
Simple Network Management Protocol is the standard/protocol for obtaining and organizing information about managed devices.
```

What is MAC Spoofing?
```
MAC addresses are written by hardware manufacturers; however, users can "mask" it on the software side so that the device appears to have a different MAC address.
```

What is ARP?
  Describe ARP poisoning/flooding?
```
Address Resolution Protocol maps IPs to MAC addresses for a LAN. ARP poisoning is where an attacker sends a "spoofed" ARP message on a LAN to associate the attacker's MAC address with the IP of another host.
```


## Cryptographic
What is SSL and how does it work?
```
Wraps TCP session in the encrypted tunnel to secure data in packets.
```

What's the difference between encoding, encrypting, and hashing? What is each used for?
```
encoding - (AVAILABILITY) reversible transformation of data format to preserve data usability
encrypting - (CONFIDENTIALITY) secure encoding of data to allow only authorized access to decrypt to reveal the original text
hashing - (INTEGRITY) one way unique(ish) summary of data used for integrity
```

How does encryption work?
  - Symmetric and Asymmetric
```
Symmetric - private key used to encrypt and decrypt
Asymmetric - a public key is used to encrypt, and a separate private key is used to decrypt
```

What is a salted hash and what does it protect against?
```
A salt is random data that is applied to a hashed password stored in the password database to protect against known hash attacks.
```


## Open-Ended Questions:
Can you list five common TCP ports and their protocols?

Choose either XSRF, XXS, Phishing, or SQL Injection attack. Describe two attacks and how to detect and prevent them.

What are some steps you would take to secure a server?

What do you know about application security?
