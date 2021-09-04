# Notes

* confidentiality, integrity, and availability of data," or the CIA triad

Step | Explanation
-----|-------------
Identifying the Risk | Identifying risks the business is exposed to, such as legal, environmental, market, regulatory, and other types of risks.
Analyze the Risk | Analyzing the risks to determine their impact and probability. The risks should be mapped to the organization's various policies, procedures, and business processes.
Evaluate the Risk | Evaluating, ranking, and prioritizing risks. Then, the organization must decide to accept (unavoidable), avoid (change plans), control (mitigate), or transfer risk (insure).
Dealing with Risk | Eliminating or containing the risks as best as possible. This is handled by interfacing directly with the stakeholders for the system or process that the risk is associated with.
Monitoring Risk | All risks must be constantly monitored. Risks should be constantly monitored for any situational changes that could change their impact score, i.e., from low to medium or high impact.


![Project Structure](pictures/Screenshot_20210904_102231.png)

## Types of shells

Shell Type | Description
-----------|------------
Reverse shell | Initiates a connection back to a "listener" on our attack box.
Bind shell | "Binds" to a specific port on the target host and waits for a connection from our attack box.
Web shell | Runs operating system commands via the web browser, typically not interactive or semi-interactive. It can also be used to run single commands (i.e., leveraging a file upload vulnerability and uploading a PHP script to run a single command.

## Ports

* A port can be thought of as a window or door on a house (the house being a remote system), if a window or door is left open or not locked correctly, we can often gain unauthorized access to a home. 

Port(s) | Protocol
--------|---------
20/21 (TCP) | FTP
22 (TCP) | SSH
23 (TCP) | Telnet
25 (TCP) | SMTP
80 (TCP) | HTTP
161 (TCP/UDP) | SNMP
389 (TCP/UDP) | LDAP
443 (TCP) | SSL/TLS (HTTPS)
445 (TCP) | SMB
3389 (TCP) | RDP

## OWASP Top 10

1. 	Injection 	SQL injection, command injection, LDAP injection, etc.
2. 	Broken Authentication 	Authentication and session management misconfigurations can lead to unauthorized access to an application through password guessing attacks or improper session timeout, among other issues.
3. 	Sensitive Data Exposure 	Improperly protecting data such as financial, healthcare, or personally identifiable information.
4. 	XML External Entities (XXE) 	Poorly configured XML processors that can lead to internal file disclosure, port scanning, remote code execution, or denial of service attacks.
5. 	Broken Access Control 	Restrictions are not appropriately implemented to prevent users from accessing other users accounts, viewing sensitive data, accessing unauthorized functionality, modifying data, etc.
6. 	Security Misconfiguration 	Insecure default configurations, open cloud storage, verbose error messages which disclose too much information.
7. 	Cross-Site Scripting (XSS) 	XSS occurs when an application does not properly sanitize user-supplied input, allowing for the execution of HTML or JavaScript in a victim's browser. This can lead to session hijacking, website defacement, redirecting a user to a malicious website, etc.
8. 	Insecure Deserialization 	This flaw often leads to remote code execution, injection attacks, or privilege escalation attacks.
9. 	Using Components with Known Vulnerabilities 	All of the components used by an application (libraries, frameworks, software modules) run with the same privilege as the application. If the application uses components with known flaws, it may lead to sensitive data exposure or remote code execution.
10. 	Insufficient Logging & Monitoring 	Deficiencies in logging & monitoring may allow a successful attack to go unnoticed, for attackers to establish persistence in the network, or tamper with or extract sensitive data without being noticed.

It is essential to become familiar with each of these categories and the various vulnerabilities that fit each. Web application vulnerabilities will be covered in-depth in later modules. To learn more about web applications, check out the Introduction to Web Applications module.
Table of Contents
Introduction
Setup
Pentesting Basics
Getting Started with Hack The Box (HTB)
Attacking Your First Box
Problem Solving
What's Next?
My Workstation

OFFLINE

1 / 1 spawns left
