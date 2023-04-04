
# Powershell
# GUIModule.psm1

## Project description

GUIModule.psm1 is a PowerShell module that provides functions for easily creating forms and graphical user interface (GUI) elements for PowerShell scripts. This tool is useful for those who want to create applications and tools based on PowerShell with a user-friendly graphical interface. In this example, we use the GUIModule.psm1 module to create a form with a username text box, an additional information text box, and buttons for resetting the password and canceling the operation. The Reset-UserPassword function is called when the "Reset Password" button is clicked, and it uses the Generate-SecurePassword function to create a new secure password.

You can use and customize the functions provided by the GUIModule.psm1 module to create a variety of GUI forms and elements to suit your specific requirements.

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

## Usage

The GUIModule.psm1 module provides a set of functions that allow you to easily create and customize GUI forms and elements in your PowerShell scripts. Below is an example script that demonstrates how to create a form to reset a user's password using functions from the GUIModule.psm1 module.

```powershell
# Place your example code here



