# Powershell
GUIModule.psm1

## Descripción del proyecto

GUIModule.psm1 es un módulo de PowerShell que proporciona funciones para crear fácilmente formularios y elementos de interfaz gráfica de usuario (GUI) para scripts de PowerShell. Esta herramienta es útil para aquellos que deseen crear aplicaciones y herramientas basadas en PowerShell con una interfaz gráfica amigable para el usuario.

## Tabla de contenidos

1. [Requisitos previos](#requisitos-previos)
2. [Instalación](#instalación)
3. [Uso](#uso)
4. [Licencia](#licencia)
5. [Contacto](#contacto)

## Requisitos previos

- PowerShell 5.1 o superior
- Módulo ActiveDirectory para PowerShell (si se utiliza en un entorno de Active Directory)

## Instalación

1. Descargue el archivo GUIModule.psm1 en su equipo local.
2. Copie el archivo GUIModule.psm1 en una de las rutas incluidas en la variable `$env:PSModulePath`, por ejemplo, `%USERPROFILE%\Documents\WindowsPowerShell\Modules\GUIModule`.
3. Abra una nueva ventana de PowerShell y ejecute el siguiente comando para importar el módulo:

   ```powershell
   Import-Module GUIModule
