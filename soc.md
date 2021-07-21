# General Open-ended Questions
Why did you choose to pursue a career in Cybersecurity?

What do you do when you are AFK?

How have you pursued cybersecurity?
- Outside of what has been required by school and work?

What career/discipline are you interested in Cyber Security?

Where do you see your self in 5 years? 10 years?

Describe your home lab set up.

# SOC L1

Check some vocab knowledge:
```
asset - what you are trying to protect
threat - something that can affect the CIA triad
vulnerability - a weakness in security program that if exploited threatens CIA triad
risk - potential for damage to the CIA triad as a result of a threat

Severity = Asset Priority * Threat Impact
Risk  = Probability *  Severity
```
What is the difference between a security event and a security incident?

```
An incident is anything that can adversely affect the CIA triad.

SOC handles events
SOC performs analysis to turn into incidents
CIRT investigates incidents
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

What is SSL and how does it work?
```
Wraps TCP session in encrypted tunnel to secure data in packets.
```
What's the difference between encoding, encrypting, and hashing?
```
encoding -
encrypting -
hasing -
```

What is the difference between a drop and a deny on a firewall?

What is the difference been a SIEM and IDS?

Define a XSRF, XXS, Phishing, SQL Injection attack and how to prevent them respectively?

What are some XXS Countermeasures:
Encoding the output
Applying filters at the point where input is received
Using appropriate response headers
Enabling content security policy
Escaping untrusted characters

What are some examples of data types in terms of  Threat Intelligence Exchanges? <br>
`email address`, `hosts`, `ip`, `filehash`, `filename`, `mutex`, `registry`.

Can you list 10 common TCP ports and their protocols.



## Open-ended Questions
What makes DNS monitoring so important?

# SOC L2
Can you write a snort signature? Yara rule?

What is a file mutex?

Can you configure IP Tables?

Can you describe a POODLE attacks?

```
Man-in-the-middle exploit to fall back to SSL 3.0.
Attacker needs to make 256 SSL 3.0 requests to reveal one byte of encrypted  messages.
```

Describe how HeartBleed works?

Name some attributes about an alert that you might use to triage it?
