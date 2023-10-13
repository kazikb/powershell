<#
Fragment kodu pozwalający na nawiązanie połączenia z instancją MSSQL Server.
Nie są wymagane dodatkowe narzędzia czy biblioteki. Wykorzystywana jest natywna klasa
.NET-a System.Data.SqlClient
#>

# Nawiązanie połączenia z instancją MSSQL
try {
    $SqlConnection = New-Object System.Data.SqlClient.SqlConnection
    $SqlConnection.ConnectionString = "Server = mssqlserver.example.local; Database = DemoDB; Integrated Security = True"
}
catch {
    Write-Error $_.Exception.Message
}

# Pobranie danych z bazy za pomocą obiektu SqlDataAdapter
try {
    $SqlCmd = New-Object System.Data.SqlClient.SqlCommand
    $SqlCmd.Connection = $SqlConnection
    $SqlCmd.CommandTimeout = 0
    $SqlCmd.CommandText = 'SELECT name FROM sys.databases'

    $SqlAdapter = New-Object System.Data.SqlClient.SqlDataAdapter
    $SqlAdapter.SelectCommand = $SqlCmd

    $SqlDataSet = New-Object System.Data.DataSet
    $SqlAdapter.Fill($SqlDataSet)
}
catch {
    Write-Error $_.Exception.Message
}

# Wykonanie zapytań
if ($SqlConnection.State -eq 'Open') {

    try {
        $SqlCommand = $SqlConnection.CreateCommand()
        $SqlCommand.CommandText = "EXEC sp_BackupDatabases @backupLocation='C:\Backup\', @databaseName='DemoDB', @backupType='F'"
        $SqlCommand.ExecuteNonQuery()
    }
    catch {
        Write-Error $_.Exception.Message
    }

}

# Zamknięcie połączenia do bazy.
$SqlConnection.Close()
