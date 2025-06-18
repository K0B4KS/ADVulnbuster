
# Powershell
# AD VULNBUSTER

![image](https://github.com/user-attachments/assets/5e9ff070-2842-4b5f-8fa5-d28ece949e02)


## Project description

AD VulnBuster is a powerful Active Directory auditing tool designed to uncover common misconfigurations and privilege escalation vectors. It detects environments vulnerable to DCSync attacks, forged ticket persistence (Golden, Silver, Diamond Tickets), PKI misconfigurations, risky ACLs, and weak Kerberos settings such as Kerberoasting and AS-REP Roasting. The tool also analyzes service accounts, GPO permissions, Resource-Based Constrained Delegation (RBCD), and provides detailed escalation path mapping, delivering a comprehensive security report of the Active Directory environment.


## Table of contents

1. [Prerequisites](#prerequsites)
2. [Installation](#installation)
3. [Use](#use)
4. [Features](#Features)
5. [License](#license)
6. [Contact](#contact)

## Prerequisites

- PowerShell 5.1 or higher
- ActiveDirectory module for PowerShell (if used in an Active Directory environment)

## Installation

1. Download the zip to your personal computer.
2. Extract and copy advulnbuster.ps1 to Domain controller.
3. The file shound localted in c:\adaudit\advulnbuster 


## Use

Run with powershell. 

![image](https://github.com/user-attachments/assets/4b8cabf8-5d52-469a-aa29-c37bf80b0015)

##Features

![image](https://github.com/user-attachments/assets/911054ac-feb4-4a77-b6d3-64eea58631f6)

. Check potential dangerous Dcsync rights in Active Directory root

. Remove Dcsync Righs

. Restore Dcsync Righs

![image](https://github.com/user-attachments/assets/3ab7dc67-5bb4-43b7-888a-71b074331afe)

Find Kerberos attack vectors:
. GoldenTicket
. SilverTicket
. DiamondTicket

![image](https://github.com/user-attachments/assets/b8a64f81-f1c6-4584-9d53-5a2e11c0fcc9)

Reporting and Auditing section.

. ACL Report: Extract complete ACL report classfied by critical assets

![image](https://github.com/user-attachments/assets/ce16ac04-8cf6-4f0d-a325-833f12b67414)


. PKI Audit Report: ESC1...ESC15 and Miss configurations 

![image](https://github.com/user-attachments/assets/b8de3c1b-0b00-46ba-a707-f2c38b6098b7)

. Complete Active Directory Auditing report and export to hmtl format

![image](https://github.com/user-attachments/assets/fc3a024e-2ac8-459e-863e-0f6b9db1638a)

![image](https://github.com/user-attachments/assets/e688e9a0-49e7-45ce-924e-ffb03385b917)


. Find Escalation Paths

![image](https://github.com/user-attachments/assets/b0b39564-3d96-481b-b991-86d0b5875c63)


. Analyze PKI vulnerabilities in templates 

![image](https://github.com/user-attachments/assets/6c67a974-997e-4a26-95d1-568fceae7b18)




## License

This project is licensed under the MIT License.

## Contact

If you have any questions or suggestions, please feel free to open an issue on the project's GitHub repository (if available) or contact the project maintainer directly.
