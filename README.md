
# Powershell
# AD VULNBUSTER

![image](https://github.com/user-attachments/assets/5e9ff070-2842-4b5f-8fa5-d28ece949e02)


## Project description

AD VulnBuster is a powerful Active Directory auditing tool designed to uncover common misconfigurations and privilege escalation vectors. It detects environments vulnerable to DCSync attacks, forged ticket persistence (Golden, Silver, Diamond Tickets), PKI misconfigurations, risky ACLs, and weak Kerberos settings such as Kerberoasting and AS-REP Roasting. The tool also analyzes service accounts, GPO permissions, Resource-Based Constrained Delegation (RBCD), and provides detailed escalation path mapping, delivering a comprehensive security report of the Active Directory environment.
You can use and customize the functions provided by the GUIModule.psm1 module to create a variety of GUI forms and elements to suit your specific requirements.

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


## Usage

Run with powershell. 

![image](https://github.com/user-attachments/assets/4b8cabf8-5d52-469a-aa29-c37bf80b0015)

##Features
- DCsync Menu -
![image](https://github.com/user-attachments/assets/911054ac-feb4-4a77-b6d3-64eea58631f6)
. Check potential dangerous Dcsync rights in Active Directory root
. Remove Dcsync Righs
. Restore Dcsync Righs


## License

This project is licensed under the MIT License.

## Contact

If you have any questions or suggestions, please feel free to open an issue on the project's GitHub repository (if available) or contact the project maintainer directly.
