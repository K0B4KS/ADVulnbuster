# Powershell
# GUIModule.psm1

## Project description

GUIModule.psm1 is a PowerShell module that provides functions for easily creating forms and graphical user interface (GUI) elements for PowerShell scripts. This tool is useful for those who want to create applications and tools based on PowerShell with a user-friendly graphical interface.

## Table of contents

1. [Prerequisites](#prerequsites)
2. [Installation](#installation)
3. [Use](#use)
4. [License](#license)
5. [Contact](#contact)

## Prerequisites

- PowerShell 5.1 or higher
- ActiveDirectory module for PowerShell (if used in an Active Directory environment)

## Installation

1. Download the GUIModule.psm1 file to your local computer.
2. Copy the GUIModule.psm1 file to one of the paths included in the $env:PSModulePath variable, for example, %USERPROFILE%\Documents\WindowsPowerShell\Modules\GUIModule.
3. Open a new PowerShell window and run the following command to import the module:

   ```powershell
   Import-Module GUIModule
