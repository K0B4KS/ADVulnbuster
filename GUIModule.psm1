<# GUIModule.psm1
# Author: Joel Caro 
# 02/03/2023
# V1 
# Instructions: 
# To use this module:
# 1. Import the module with "Import-Module .\GUIModule.psm1".
# 2. Create a form with "New-ScriptForm".
# 3. Add controls to the form using the "Add-*" functions.
# 4. Display the form with "Show-ScriptForm".
# 5. Use the calculation functions to adjust the form size.

function New-ScriptForm {
    # ...
}

function Calculate-ScriptFormSize {
    # ...
}

function Add-ScriptButton {
    # ...
}

function Add-ScriptLabel {
    # ...
}

function Add-scriptTextBox {
    # ...
}

function Show-scriptForm {
    # ...
}

function Add-ScriptCheckBox {
    # ...
}

Export-ModuleMember -Function New-ScriptForm, Show-ScriptForm, Add-scriptLabel, Add-scriptButton, Add-scriptTextBox, Calculate-scriptFormSize

Example of Usage with simple script

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

# Add new textbox
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
#>

Install-Module PS2EXE -Scope CurrentUser

function New-ScriptForm {
    param (
        [string] $Title = "New Form",
        [int] $Width,
        [int] $Height,
        [scriptblock] $CalculateFormSize
    )

    $form = New-Object System.Windows.Forms.Form
    $form.Text = $Title

    if ($Width -and $Height) {
        $form.Size = New-Object System.Drawing.Size($Width, $Height)
    }

    if ($CalculateFormSize) {
        $form.CalculateFormSize = $CalculateFormSize
    }

    return $form
}

function Measure-ScriptFormSize {
    param (
        [System.Windows.Forms.Form] $Form
    )

    $formWidth = 0
    $formHeight = 0

    foreach ($control in $Form.Controls) {
        $controlRight = $control.Location.X + $control.Size.Width
        $controlBottom = $control.Location.Y + $control.Size.Height

        if ($controlRight -gt $formWidth) {
            $formWidth = $controlRight
        }

        if ($controlBottom -gt $formHeight) {
            $formHeight = $controlBottom
        }
    }

    $formWidth += 30
    $formHeight += 70

    return (New-Object System.Drawing.Size($formWidth, $formHeight))
}

function Add-ScriptButton {
    param (
        $Form,
        [string] $Text,
        [System.Drawing.Point] $Location,
        [scriptblock] $OnClick
    )

    $button = New-Object System.Windows.Forms.Button
    $button.Text = $Text
    $button.Location = $Location
    $button.Add_Click($OnClick)
    $Form.Controls.Add($button)
}

function Add-ScriptLabel {
    param (
        $Form,
        [string] $Text,
        [System.Drawing.Point] $Location
    )

    $label = New-Object System.Windows.Forms.Label
    $label.Text = $Text
    $label.AutoSize = $true
    $label.Location = $Location
    $Form.Controls.Add($label)
}

function Add-scriptTextBox {
    param (
        $Form,
        [System.Drawing.Point] $Location,
        [System.Drawing.Size] $Size
    )

    $textBox = New-Object System.Windows.Forms.TextBox
    $textBox.Location = $Location
    $textBox.Size = $Size
    $Form.Controls.Add($textBox)

    return $textBox
}

function Show-scriptForm {
    param (
        $Form
    )

    $Form.ShowDialog()
}

function Add-ScriptCheckBox {
    param (
        $Form,
        [string] $Text,
        [System.Drawing.Point] $Location
    )

    $checkBox = New-Object System.Windows.Forms.CheckBox
    $checkBox.Text = $Text
    $checkBox.AutoSize = $true
    $checkBox.Location = $Location
    $Form.Controls.Add($checkBox)

    return $checkBox
}

# Add-ScriptGroupBox: Adds a container in the form of a group box to visually organize other related controls.

function Add-ScriptGroupBox {
    param (
        $Form,
        [string] $Text,
        [System.Drawing.Point] $Location,
        [System.Drawing.Size] $Size
    )

    $groupBox = New-Object System.Windows.Forms.GroupBox
    $groupBox.Text = $Text
    $groupBox.Location = $Location
    $groupBox.Size = $Size
    $Form.Controls.Add($groupBox)

    return $groupBox
}

#Add-ScriptDateTimePicker: Add a date and time picker control.

function Add-ScriptDateTimePicker {
    param (
        $Form,
        [System.Drawing.Point] $Location,
        [System.Drawing.Size] $Size
    )

    $dateTimePicker = New-Object System.Windows.Forms.DateTimePicker
    $dateTimePicker.Location = $Location
    $dateTimePicker.Size = $Size
    $Form.Controls.Add($dateTimePicker)

    return $dateTimePicker
}

#Add-Script Progress Bar: Add a progress bar to show the progress of a task.

function Add-ScriptProgressBar {
    param (
        $Form,
        [System.Drawing.Point] $Location,
        [System.Drawing.Size] $Size
    )

    $progressBar = New-Object System.Windows.Forms.ProgressBar
    $progressBar.Location = $Location
    $progressBar.Size = $Size
    $Form.Controls.Add($progressBar)

    return $progressBar
}

function Add-ScriptRadioButton {
    param (
        $Form,
        [string] $Text,
        [System.Drawing.Point] $Location,
        [System.Windows.Forms.GroupBox] $GroupBox
    )

    $radioButton = New-Object System.Windows.Forms.RadioButton
    $radioButton.Text = $Text
    $radioButton.Location = $Location
    $radioButton.AutoSize = $true

    if ($GroupBox) {
        $GroupBox.Controls.Add($radioButton)
    } else {
        $Form.Controls.Add($radioButton)
    }

    return $radioButton
}



Export-ModuleMember -Function New-ScriptForm, Show-ScriptForm, Add-scriptLabel, Add-scriptButton, Add-scriptTextBox, Measure-scriptFormSize, Add-ScriptGroupBox, Add-ScriptDateTimePicker, Add-ScriptProgressBar, Create-Installer, Add-ScriptCheckBox, Add-ScriptRadioButton


