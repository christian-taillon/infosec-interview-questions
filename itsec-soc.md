# SOC L1

### Basic Vocab
```
asset - what you are trying to protect
threat - something that can affect the CIA triad
vulnerability - a weakness or flaw in a security program that, if exploited, threatens the CIA triad
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
Worm - a virus that can spread over a network, often targetting known exploits
Trojan - program pretending to be legitimate or desired software
Bots - program performing automated tasks (no direct human interaction required)
Botnet - collections of bots
Cryptominer - Malware that mines cryptocurrency on a users device on behalf of an adversary
Scareware - makes false claims about a virus infecting a device, typically involving a request for payment to solve the issue.
Ransomware (targets Availability) - Malware that encrypts a file system allowing adversaries to require companies to pay a ransom for a decryption key
Extortionware/leakware, aka. Double Extortion Ransomware (targets CONFIDENTIALITY) - like ransomware but also involves malware uploading encrypted data (or part of encrypted data) to be released to the public if the target doesn't pay

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
`email address, `hosts`, `ip`, `filehash`, `filename`, `mutex`, `registry`, `url`, `cidr`, `email subject`, `user-agent`

Generally speaking, are some other Indicators of Compromise in the environment?
```
Answers along the lines of:
Unusual, rare, or otherwise anomalous rhythmic DNS requests
Unusual, rare, or otherwise anomalous network traffic
Impossible Travel Events
Unknown and unapproved applications on a system
A surge in Invalid login or access attempts
A surge in domain activity from an entity
New and Unapproved User Account Creation
Suspicious Registry changes
etc...
```

What event logs are available (by default) on Windows Operating Systems?
```
Security | Applicatoin | System
```

List some common Windows Event Log Codes.
```
Event ID :	Desc
4624	Successful account log on
4625	Failed account log on
4634	An account logged off
4648	A logon attempt was made with explicit credentials
4719	System audit policy was changed.
4964	A special group has been assigned to a new log on
1102	Audit log was cleared. This can relate to a potential attack
4720	A user account was created
4722	A user account was enabled
4723	An attempt was made to change the password of an account
4725	A user account was disabled
4728	A user was added to a privileged global group
4732	A user was added to a privileged local group
4756	A user was added to a privileged universal group
4738	A user account was changed
4740	A user account was locked out
4767	A user account was unlocked
4735	A privileged local group was modified
4737	A privileged global group was modified
4755	A privileged universal group was modified
4772	A Kerberos authentication ticket request failed
4777	The domain controller failed to validate the credentials of an account.
4782	Password hash an account was accessed
4616	System time was changed
4657	A registry value was changed
4697	An attempt was made to install a service
4698, 4699, 4700, 4701, 4702	Events related to Windows scheduled tasks being created, modified, deleted, enabled or disabled
4946	A rule was added to the Windows Firewall exception list
4947	A rule was modified in the Windows Firewall exception list
4950	A setting was changed in Windows Firewall
4954	Group Policy settings for Windows Firewall has changed
5025	The Windows Firewall service has been stopped
```

Tell us about some controls that are commonly used to secure a company.
```
Firewall|Anti-Virus|EDR|NDR|Proxy|ESG|IDS/IPS|secret managers|SIEM|App Whitelisting|Script Control|UBA/UEBA|CASB|Vulnerability Scanners|MFA/2FA|SOAR|etc
```
## Detection
What is the difference between IDS and IPS?

```
IDS - detects security events
IPS - has the capability to block security events
```


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

## Triage
What sources might you use to examine the reputation of a filehash or ip?

```
VirusTotal|OTX|Cymon|PassiveTotal|ThreatConnect|Threat Crowd|Threat Miner|IBM X-Force|Talos
```

What resources might you use to analyze a file dynamically?
```
Hybrid Analysis | Any.Run | Joe's Sandbox | OPSWAT
```

## Containment | Remediation | Escalation
How would you defend our network from that IP if there was an attack from a specific IP address?
```
Block the IP addresses
```

What is the difference between dropping traffic and denying/rejecting traffic on a firewall?

```
deny - will send an ICMP type 3 (destination unreachable) response
drop - no notification of denial / silently stops traffic
```

What are some SQL Injection Types?
```
In-band | Inferential | Out-of-Band
```

How do you prevent SQL Injection Attacks?

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
Wraps TCP session an encrypted tunnel to secure data in packets.
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

What is a salted hash, and what does it protect against?
```
A salt is random data that is applied to a hashed password stored in the password database to protect against known hash attacks.
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
  At what layer does this protocol exist `network.`
```
Simple Network Management Protocol is the standard / protocol for obtaining and organizing information about managed devices.
```

What is MAC Spoofing?
```
Hardware manufacturers write MAC addresses; however, users can "mask" it on the software side so that the device appears to have a different MAC address.
```

What is ARP?
  Describe ARP poisoning/flooding?
```
Address Resolution Protocol maps IPs to MAC addresses for a LAN. ARP poisoning is where an attacker sends a "spoofed" ARP message on a LAN to associate the attacker's MAC address with the IP of another host.
```

## Open-Ended Questions:
Can you list five common TCP ports and their protocols?

Choose either XSRF, XXS, Phishing, or SQL Injection attack. Describe two attacks and how to detect and prevent them.

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
The attacker needs to make 256 SSL 3.0 requests to reveal one byte of encrypted messages.
```

Describe how HeartBleed works.

What makes DNS monitoring so important? (Open ended)

Name some attributes about an alert that you might use to triage it.
