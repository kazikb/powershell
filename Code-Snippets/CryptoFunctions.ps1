#Requires -Version 5.1

# Trochę zabawy z kryptografią i PowerShell

# Funkcja do generowania haseł
# Source: https://rosettacode.org/wiki/Password_generator#PowerShell
function New-RandomPassword
{
    [CmdletBinding()]
    [OutputType([string])]
    Param
    (
        [Parameter(Mandatory=$false)]
        [ValidateRange(1,[Int]::MaxValue)]
        [Alias("l")]
        [int]
        $Length = 8,

        [Parameter(Mandatory=$false)]
        [ValidateRange(1,[Int]::MaxValue)]
        [Alias("n","c")]
        [int]
        $Count = 1,

        [Parameter(Mandatory=$false)]
        [Alias("s")]
        [string[]]
        $Source = @("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789", "!\`"#$%&'()*+,-./:;<=>?@[]^_{|}~"),

        [Parameter(Mandatory=$false)]
        [Alias("x")]
        [switch]
        $ExcludeSimilar
    )

    Begin
    {
        [char[][]] $charArrays = $Source
        [char[]]   $allChars   = $charArrays | ForEach-Object {$_}
        [char[]]   $similar    = "Il1O05S2Z".ToCharArray()

        $random = New-Object -TypeName System.Security.Cryptography.RNGCryptoServiceProvider

        function Get-Seed
        {
            $bytes = New-Object -TypeName System.Byte[] -Argument 4
            $random.GetBytes($bytes)
            [BitConverter]::ToUInt32($bytes, 0)
        }

        function Add-PasswordCharacter ([char[]]$From)
        {
            $key = Get-Seed

            while ($password.ContainsKey($key))
            {
                $key = Get-Seed
            }

            $index = (Get-Seed) % $From.Count

            if ($ExcludeSimilar)
            {
                while ($From[$index] -in $similar)
                {
                    $index = (Get-Seed) % $From.Count
                }
            }

            $password.Add($key, $From[$index])
        }
    }
    Process
    {
        for ($i = 1;$i -le $Count; $i++)
        {
            [hashtable] $password = @{}

            foreach ($array in $charArrays)
            {
                if($password.Count -lt $Length)
                {
                    Add-PasswordCharacter -From $array # Append to $password
                }
            }

            for ($j = $password.Count; $j -lt $Length; $j++)
            {
                Add-PasswordCharacter -From $allChars  # Append to $password
            }

            ($password.GetEnumerator() | Select-Object -ExpandProperty Value) -join ""
        }
    }
}

# Reference:
# https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rngcryptoserviceprovider?view=netcore-3.1
# https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.rfc2898derivebytes?view=netcore-3.1
# https://docs.microsoft.com/en-us/dotnet/api/system.security.cryptography.aes?view=netcore-3.1

function Protect-DataWithAESEncryption {
    param (
        [Parameter(ParameterSetName='Passphrase',
                    Mandatory=$true)]
        [SecureString]$EncryptionPassphrase,

        [Parameter(ParameterSetName='PKI',
                    Mandatory=$true)]
        [String]$CertThumbprint,
        [Parameter(ParameterSetName='PKI',
                    Mandatory=$false)]
        [ValidateSet("LocalMachine","CurrentUser")]
        [String]$CertStore="CurrentUser",

        [Parameter(Mandatory=$true)]
        $InputData
    )

    $RNG = New-Object System.Security.Cryptography.RNGCryptoServiceProvider

    # 16 Bytes (128-bit) - IV i Salt
    # Zalecane minimum to 8 Bytes
    $InitializationVector = [System.Byte[]]::new(16)
    $RNG.GetBytes($InitializationVector)

    if ($PSCmdlet.ParameterSetName -eq "PKI") {
        if ($CertStore -eq "CurrentUser") {
            $Cert = Get-Item -Path "Cert:\CurrentUser\My\$CertThumbprint" -ErrorAction Stop
        }
        elseif ($CertStore -eq "LocalMachine") {
            $Cert = Get-Item -Path "Cert:\LocalMachine\My\$CertThumbprint" -ErrorAction Stop
        }

        # 32 Bytes (256-bit) klucz szyfrujacy AES
        $AESEncryptionKey     = [System.Byte[]]::new(32)
        $RNG.GetBytes($AESEncryptionKey)

        try {
            # Szyfrowanie klucza AES za pomocą klucza publicznego certyfikatu
            $PKIencryptedKey = $Cert.PublicKey.Key.Encrypt($AESEncryptionKey, $true)

            # Kodowanie klucza do Base64
            $EncryptedKey = [System.Convert]::ToBase64String($PKIencryptedKey)
        }
        catch {
            Write-Error "Nie mozna zaszyfrowac kluczem publicznym klucza szyfrujacego AES."
            return
        }
    } else {
        # Konwersja z obiektu SecureString -> String wymagana przez argument funkcji Rfc2898DeriveBytes
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncryptionPassphrase)

        # Utworzenie 32 Bytes (256-bit) klucza z podanej frazy wejściowej.
        # Salt jest taki sam jak IV
        $DeriveBytes = New-Object Security.Cryptography.Rfc2898DeriveBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR), $InitializationVector, 2000)
        $AESEncryptionKey = $DeriveBytes.GetBytes(32)

        $EncryptionPassphrase.Dispose()
        $EncryptedKey = ""
    }

    # Utworzenie i zainicjowanie AesCryptoServiceProvider
    $AESCipher = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $AESCipher.Key = $AESEncryptionKey
    $AESCipher.IV = $InitializationVector

    try {
        # Konwersja danych wejściowych na Byty z zachowaniem kodowania UTF8
        $UnencryptedBytes = [System.Text.Encoding]::UTF8.GetBytes($InputData)

        # Zaszyfeowanie danych
        $Encryptor = $AESCipher.CreateEncryptor()
        $EncryptedBytes = $Encryptor.TransformFinalBlock($UnencryptedBytes, 0, $UnencryptedBytes.Length)

        # Przygotowanie danych wyjsciowych:
        # Bytes [0-15] - wartość IV
        # Bytes [15 < ] - Zaszyfrowane dane
        [byte[]] $FullData = $AESCipher.IV + $EncryptedBytes

        $CipherText = [System.Convert]::ToBase64String($FullData)

        return [PSCustomObject]@{
            Key = $EncryptedKey
            CipherText = $CipherText
        }
    }
    catch {
        Write-Error "Nie mozna zaszyfrowac danych."
    }
    finally {
        # Czyszczenie obiektów kryptograficznych
        $AESCipher.Dispose()
        $Encryptor.Dispose()
        $RNG.Dispose()
        if ($DeriveBytes) {$DeriveBytes.Dispose()}
        if ($null -ne $AESEncryptionKey) { [array]::Clear($AESEncryptionKey, 0, $AESEncryptionKey.Length) }
    }
}

function Unprotect-DataWithAESEncryption {
    param (
        [Parameter(ParameterSetName='Passphrase',
                    Mandatory=$true)]
        [SecureString]$EncryptionPassphrase,

        [Parameter(ParameterSetName='PKI',
                    Mandatory=$true)]
        [String]$CertThumbprint,
        [Parameter(ParameterSetName='PKI',
                    Mandatory=$false)]
        [ValidateSet("LocalMachine","CurrentUser")]
        [String]$CertStore="CurrentUser",
        [Parameter(ParameterSetName='PKI',
                    Mandatory=$true)]
        [String]$EncryptedKey,

        [Parameter(Mandatory=$true)]
        $InputData
    )
    # Odczytanie wartości IV i Salt z pierwszych 15 Bytes danych wejściowych.
    $EncryptedBytes = [System.Convert]::FromBase64String($InputData)
    $InitializationVector = $EncryptedBytes[0..15]

    if ($PSCmdlet.ParameterSetName -eq "PKI") {
        if ($CertStore -eq "CurrentUser") {
            $Cert = Get-Item -Path "Cert:\CurrentUser\My\$CertThumbprint" -ErrorAction Stop
        }
        elseif ($CertStore -eq "LocalMachine") {
            $Cert = Get-Item -Path "Cert:\LocalMachine\My\$CertThumbprint" -ErrorAction Stop
        }

        # Odkodowanie klucza z Base64
        $PKIEncryptedKey  = [System.Convert]::FromBase64String($EncryptedKey)

        # Odszyfrowanie klucza AES za pomocą klucza prywatnego certyfikatu
        try {
            $AESEncryptionKey = $Cert.PrivateKey.Decrypt($PKIEncryptedKey, $true)
        }
        catch {
            Write-Error "Nie moge odszyfrowac klucza szyfrujacego AES kluczem prywatnym. Upewnij sie ze zostal wybrany wlasciwy certyfikat."
            return
        }
    } else {
        # Konwersja z obiektu SecureString -> String wymagana przez argument funkcji Rfc2898DeriveBytes
        $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($EncryptionPassphrase)

        # Utworzenie 32 Bytes (256-bit) klucza z podanej frazy wejściowej.
        # Salt jest taki sam jak IV
        $DeriveBytes = New-Object Security.Cryptography.Rfc2898DeriveBytes([System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR), $InitializationVector, 2000)
        $AESEncryptionKey = $DeriveBytes.GetBytes(32)

        $EncryptionPassphrase.Dispose()
    }

    $AESCipher = New-Object System.Security.Cryptography.AesCryptoServiceProvider
    $AESCipher.Key = $AESEncryptionKey
    $AESCipher.IV = $InitializationVector

    try {
        # Odszyfrowanie danych
        $Decryptor = $AESCipher.CreateDecryptor();
        $UnencryptedBytes = $Decryptor.TransformFinalBlock($EncryptedBytes, 16, $EncryptedBytes.Length - 16)

        # Konwersja odszyfrowanych Byte-ów na String wyjściowy
        $PlainText = [System.Text.Encoding]::UTF8.GetString($UnencryptedBytes)
        return $PlainText
    }
    catch {
        Write-Error "Nie mozna odszyfrowac danych. Uperwnij sie ze EncryptionPassphrase jest prawidlowe."
    }
    finally {
        # Czyszczenie obiektów kryptograficznych
        $AESCipher.Dispose()
        $Decryptor.Dispose()
        if ($DeriveBytes) {$DeriveBytes.Dispose()}
        if ($null -ne $AESEncryptionKey) { [array]::Clear($AESEncryptionKey, 0, $AESEncryptionKey.Length) }
    }
}


# Tworzenie certyfikatu Self Signed do testów
$TestCertCN = "CryptoFunctionsTest"
$TestCert = Get-ChildItem "Cert:\CurrentUser\My\" | Where-Object {$_.Subject -eq "CN=CryptoFunctionsTest"}

if ($TestCert) {
    "Pobieranie Thumbprint-a certyfikatu:"
    $TestCertThumbprint = $TestCert.Thumbprint
} else {
    "Tworzenie testowego certyfikatu:"

    $CertParam = @{
        DnsName = $TestCertCN
        CertStoreLocation = "Cert:\CurrentUser\My"
        KeyUsage = "KeyEncipherment","DataEncipherment"
        Provider = "Microsoft Enhanced RSA and AES Cryptographic Provider"
        KeyExportPolicy = "Exportable"
        HashAlgorithm = "SHA256"
    }
    New-SelfSignedCertificate @CertParam
    $TestCert = Get-ChildItem "Cert:\CurrentUser\My\" | Where-Object {$_.Subject -eq "CN=$TestCertCN"}
    $TestCertThumbprint = $TestCert.Thumbprint
}

# Testy wykorzystania funkcji
$ErrorActionPreference = "Continue"

$InputData = [PSCustomObject]@{
    Name = "Simple Name"
    Param1 = "Param1 Value"
    Param2 = "Param2 Value"
    Param3 = "Param3 Value"
} | ConvertTo-Json
"`nTest InputData:"
$InputData

"`n[*] Passphrase Encrypt`n"
$cText = Protect-DataWithAESEncryption -EncryptionPassphrase (ConvertTo-SecureString "MojeSecretPass" -AsPlainText -Force) -InputData $InputData
"Encoded Key:"
$cText.Key
"Encoded Text:"
$cText.CipherText

$cText | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\PassphraseEncoded.json" -Force -Encoding utf8

"`n[*] Passphrase Decrypt`n"
$pText = Unprotect-DataWithAESEncryption -EncryptionPassphrase (ConvertTo-SecureString "MojeSecretPass" -AsPlainText -Force) -InputData $cText.CipherText
"Decoded Text:"
$pText

"`n[*] PKI Encrypt`n"
$cText = Protect-DataWithAESEncryption -CertThumbprint $TestCertThumbprint -InputData $InputData
"Encoded Key:"
$cText.Key
"Encoded Text:"
$cText.CipherText

$cText | ConvertTo-Json | Out-File -FilePath "$PSScriptRoot\PKIEncoded.json" -Force -Encoding utf8

"`n[*] PKI Decrypt`n"
$pText = Unprotect-DataWithAESEncryption -CertThumbprint $TestCertThumbprint -EncryptedKey $cText.Key -InputData $cText.CipherText
"Decoded Text:"
$pText
