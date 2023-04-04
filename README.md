
# Powershell
# GUIModule_v1.0.psm1

## Project description

GUIModule_v1.0.psm1 is a first version of PowerShell module that provides functions for easily creating forms and graphical user interface (GUI) elements for PowerShell scripts. This tool is useful for those who want to create applications and tools based on PowerShell with a user-friendly graphical interface. In this example, we use the GUIModule.psm1 module to create a form with a username text box, an additional information text box, and buttons for resetting the password and canceling the operation. The Reset-UserPassword function is called when the "Reset Password" button is clicked, and it uses the Generate-SecurePassword function to create a new secure password.

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

Create a new form using the New-ScriptForm function.
Add controls to the form using the Add-* functions (e.g., Add-ScriptButton, Add-ScriptLabel, Add-ScriptTextBox, etc.).
Display the form using the Show-ScriptForm function.
Use the provided calculation functions to adjust the form's size, if needed.
Refer to the comments and examples within the GUIModule.psm1 script for more detailed usage instructions and examples.

## License

This project is licensed under the MIT License.

## Contact

If you have any questions or suggestions, please feel free to open an issue on the project's GitHub repository (if available) or contact the project maintainer directly.
