
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

## Usage

The GUIModule.psm1 module provides a set of functions that allow you to easily create and customize GUI forms and elements in your PowerShell scripts. Below is an example script that demonstrates how to create a form to reset a user's password using functions from the GUIModule.psm1 module.

```powershell
function Generate-SecurePassword {
    param (
        [int] $Length
    )

    $chars = 'abcdefghiklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()'
    $securePassword = -join ((1..$Length) | ForEach-Object { Get-Random -InputObject ($chars.ToCharArray()) })

    return $securePassword
}

function Reset-UserPassword {
    param (
        [string] $Username
    )

    if ([string]::IsNullOrEmpty($Username)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a valid username.", "Error", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Error)
        return
    }

    $securePassword = Generate-SecurePassword -Length 24

    # Reset User password
    # Set-ADAccountPassword -Identity $Username -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $securePassword -Force)

    Write-Host "Password for $Username has been reset to $securePassword."
    [System.Windows.Forms.MessageBox]::Show("Password for $Username has been reset successfully.", "Success", [System.Windows.Forms.MessageBoxButtons]::OK, [System.Windows.Forms.MessageBoxIcon]::Information)
}

$form = New-ScriptForm -Title "Reset Password" -Width 400 -Height 200

Add-ScriptLabel -Form $form -Text "Username:" -Location (New-Object System.Drawing.Point(10, 20))
$usernameTextBox = Add-scriptTextBox -Form $form -Location (New-Object System.Drawing.Point(10, 50)) -Size (New-Object System.Drawing.Size(350, 20))

# Add the new TextBox
Add-scriptLabel -Form $form -Text "Additional Info:" -Location (New-Object System.Drawing.Point(10, 80))
$additionalInfoTextBox = Add-scriptTextBox -Form $form -Location (New-Object System.Drawing.Point(10, 110)) -Size (New-Object System.Drawing.Size(350, 20))

Add-scriptButton -Form $form -Text "Reset Password" -Location (New-Object System.Drawing.Point(10, 150)) -OnClick {
    Reset-UserPassword -Username $usernameTextBox.Text
}

Add-scriptButton -Form $form -Text "Cancel" -Location (New-Object System.Drawing.Point(110, 150)) -OnClick {
    $form.Close()
}

$form.Size = Measure-scriptFormSize -Form $form

Show-scriptForm -Form $form

In this example, we use the GUIModule.psm1 module to create a form with a username text box, an additional information text box, and buttons for resetting the password and canceling the operation. The Reset-UserPassword function is called when the "Reset Password" button is clicked, and it uses the Generate-SecurePassword function to create a new secure password.

You can use and customize the functions provided by the GUIModule.psm1 module to create a variety of GUI forms and elements to suit your specific requirements.
