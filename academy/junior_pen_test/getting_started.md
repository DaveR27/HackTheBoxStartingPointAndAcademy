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