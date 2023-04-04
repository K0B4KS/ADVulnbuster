
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
Después de importar el módulo GUIModule, puede utilizar las funciones proporcionadas para crear y personalizar formularios y elementos de la GUI en sus scripts de PowerShell. A continuación, se muestra un ejemplo de cómo crear un formulario básico con un botón:

```powershell
Import-Module GUIModule
$form = New-ScriptForm -Text "Mi formulario" -Size (New-Object System.Drawing.Size(300, 200))
$button = Add-ScriptButton -Form $form -Text "Mi botón" -Location (New-Object System.Drawing.Point(100, 100))
Show-ScriptForm -Form $form

Consulte la documentación de cada función dentro del módulo GUIModule.psm1 para obtener más información sobre cómo utilizar y personalizar los elementos de la GUI.

## License
Este proyecto está bajo la licencia MIT. Consulte el archivo LICENSE para obtener más detalles.

## Contact
Si tiene alguna pregunta, comentario o sugerencia, no dude en ponerse en contacto conmigo a través de mi dirección de correo electrónico: ejemplo@email.com



