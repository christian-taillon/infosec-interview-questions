# SOC L1

### Basic Vocab
```
asset - what you are trying to protect
threat - something that can affect the CIA triad
vulnerability - a weakness or flaw in a security program that, if exploited, threatens CIA triad
risk - a potential for damage to the CIA triad as a result of a threat
exploit - program/code designed to take advantage of a vulnerability

Severity = Asset Priority * Threat Impact
Risk  = Probability *  Severity
```

What is the CIA Triad?
```
Confidentiality | Integrity | Availability
```

What are some types of Malware that you can tell me about?
  - followup: ...besides ransomware.
```
Malware - Malicious Software
PUP - Potentially Unwanted Program
Adware - serves unwanted or malicious advertising
Virus - infects other programs to copy its self
Worm - like a virus but can spread over network often targetting known exploits
Trojan - program pretending to be legitimate or desired software
Bots - program performing automated tasks (no direct human interaction required)
Botnet - collections of bots
Cryptominer - malware that mines crypto currency on a users device on behalf of an adversary
Scareware - makes false claims about virus infecting a device typically involving a request for payment to solve the issue
Ransomware (targets Availability) - malware that encrypts a file system allowing adversaries to require companies pay a ransom for decryption key
Extortionware/leakware aka. Double Extortion Ransomware (targets CONFIDENTIALITY) - like ransomware but also involves malware uploading encrypted data (or part of encrypted data) to be released to the public if target doesn't pay

```

What is an IoC?

```
A piece of observable forensics that suggests an endpoint or environment may have been compromised.  
```

What is the difference between IoC and an IoA?

```
IoC - Indicates Compromise
IoA - Indicator of Attack
```



What are some of the common examples of a Cyber Observables Indicator (aka IoC/IoA)? <br>
`email address`, `hosts`, `ip`, `filehash`, `filename`, `mutex`, `registry`, `url`, `cidr`, `email subject`, `user-agent`

Generally speaking, are some other Indicators of Compromise in environment?
```
Answers along the lines of:
Unusual, rare, or otherwise anomalous rhythmic DNS requests
Unusual, rare, or otherwise anomalous network traffic
Impossible Travel Events
Unknown and unapproved applications on a system
Surge in invalid login or access attempts
Surge in domain activity from entity
New and Unapproved User Account creation
Individual devices or machines usual files or network resources
Suspicious Registry changes
etc...
```


Tell us about some controls that are commonly used to secure a company.
```
Firewall|Anti-Virus|EDR|NDR|Proxy|ESG|IDS/IPS|secret managers|SIEM|App Whitelisting|Script Control|UBA/UEBA|CASB|Vulnerability Scanners|MFA/2FA|SOAR|etc
```
## Detection
What is the difference between IDS and IPS?

```
IDS - detects security events
IPS - has capability to block security events
```


What is the difference been a SIEM and IDS and IPS?

```
SIEM - combines security information management and security event management - collects and aggregates events for alerting, analysis / investigation
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

## Triage
What sources might you use to examine the reputaton of a filehash or ip?

```
VirusTotal|OTX|Cymon|PassiveTotal|ThreatConnect|Threat Crowd|Threat Miner|IBM X-Force|Talos
```

What resources might you use to dynamically analyze a file?
```
Hybrid Analysis | Any.Run | Joe's Sanbox | Opswat
```

## Containment | Remediation | Escalation
If there was an attack from a specific IP address, how would you defend our network from that IP?
```
Block the IP addresses
```

What is the difference between a droping traffic and denying / rejecting traffic on a firewall?

```
deny - will send an ICMP type 3 (destination unreachable) response
drop - no notification of denial / silently stops traffic
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

## Cryptographic
What is SSL and how does it work?
```
Wraps TCP session in encrypted tunnel to secure data in packets.
```

What's the difference between encoding, encrypting, and hashing? What is each used for?
```
encoding - (AVAILABILITY) reversible transformation of data format to preserve data usability
encrypting - (CONFIDENTIALITY) secure encoding of data to allow only authorized access to decrypt to reveal original text
hasing - (INTEGRITY) one way unique(ish) summary of data used for integrity
```

How does encryption work?
  - Symmetric and Asymmetric
```
Symmetric - private key used to encrypt and decrypt
Asymmetric - a public key is used to encrypt and a separate private key is used to decrypt
```

What is a salted hash and what does it protect against?
```
A salt is random data that is applied to a hashed password stored in the password database to protect against known hash attacks
```



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

What is SNMP?
  At what layer does this protocol exist `network`
```
Simple Network Management Protocol is standard / protocol for obtaining and organizing information about managed devices.
```

What is MAC Spoofing?
```
MAC addresses are written by hardware manufactures; however, users can "mask" it on the software side so that the device appears to have a different MAC address.
```

What is ARP?
  Describe ARP poisoning / flooding?
```
Address Resolution Protocol maps IPs to MAC addresses for a LAN. ARP poisoning is where an attacker sends a "spoofed" ARP message on a LAN to associate the attacker's MAC address with the IP of another host.
```

## Open-Ended Questions:
Can you list 5 common TCP ports and their protocols.

Choose either XSRF, XXS, Phishing, SQL Injection attack. Describe two attacks and how to detect and prevent them?

What are some steps you would take to secure a server?

What do you know about application security?


# SOC L2
Can you write a snort signature?

Can you write a Yara rule?

What is a file mutex?

Can you configure IP Tables?

Can you describe a POODLE attacks?

```
Man-in-the-middle exploit to fall back to SSL 3.0.
Attacker needs to make 256 SSL 3.0 requests to reveal one byte of encrypted  messages.
```

Describe how HeartBleed works?

What makes DNS monitoring so important?

Name some attributes about an alert that you might use to triage it?
