# PasswordGenerator
Flexible password generation library.  To make passwords XML safe the following characters (<,>,&) have been excluded from the special characters set.  To help avoid confusing passwords, the following characters (I,l,O,0) have been excluded from the various character sets.

A default static method is available, GeneratePassword(), that will generate a password using the default password generation parameters:

- minimumLengthPassword = 12
- maximumLengthPassword = 24
- minimumLowerCaseChars = 2
- minimumUpperCaseChars = 2
- minimumNumericChars = 2
- minimumSpecialChars = 2

Alternatively, you can initialize this library with a custom set of password parameters for meeting a specific application requirement.

## Usage Examples:

### PowerShell
#### Default password parameters
```powershell
[Reflection.Assembly]::LoadFile("c:\storage\PasswordGenerator.dll")
[string] $randomPW = [PasswordGenerator.PasswordGenerator]::GeneratePassword()
```

#### Specific password length and other default parameters
```powershell
[Reflection.Assembly]::LoadFile("c:\storage\PasswordGenerator.dll")
[string] $randomPW = [PasswordGenerator.PasswordGenerator]::GeneratePassword(25)
```

#### Custom password parameters
```powershell
[Reflection.Assembly]::LoadFile("c:\storage\PasswordGenerator.dll")
$minimumLengthPassword = 16
$maximumLengthPassword = 24
$minimumLowerCaseChars = 2
$minimumUpperCaseChars = 2
$minimumNumericChars = 2
$minimumSpecialChars = 2

[PasswordGenerator.PasswordGenerator]$pw = [PasswordGenerator.PasswordGenerator]::new(
    $minimumLengthPassword, 
    $maximumLengthPassword,
    $minimumLowerCaseChars,
    $minimumUpperCaseChars,
    $minimumNumericChars,
    $minimumSpecialChars)
    
[string] $randomPW = $pw.Generate()
```

### C#
#### Default password parameters
```c#
var pw = new PasswordGenerator.PasswordGenerator();
string randomPW = pw.GeneratePassword();
```
#### Custom password parameters
```c#
var generator = new PasswordGenerator.PasswordGenerator(
    minimumLengthPassword: 15,
    maximumLengthPassword: 20,
    minimumUpperCaseChars: 2,
    minimumNumericChars: 3,
    minimumSpecialChars: 2);

string randomPW = generator.Generate();
```
