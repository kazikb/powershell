# Zamiast używać tradycyjnych list w postaci takich jak w sekcji #region bad lepiej zastosować jedno z rozwiązań
# znajdujących się w sekcji #region good
# Dodatkowe info o tablicach i listach:
# https://powershellexplained.com/2018-10-15-Powershell-arrays-Everything-you-wanted-to-know/#arraylist
#
# Dodatkowo ArrayList został oznaczony jako deprecated i lepiej korzystać z Generic.List

#region bad
# Najgorsze pod względem wydajności, można stosować dla małej liczby obiektów.
$array = @()
foreach ($user in $userList) {
    $array += [PSCustomObject]@{
        Username = $user.Name
        Email = $user.SamAccountName
    }
}
#endregion bad

#region good
# Lepsze i wydajniejsze rozwiązania
$array = foreach ($user in $userList) {
    [PSCustomObject]@{
        Username = $user.Name
        Email = $user.SamAccountName
    }
}

# Najlepsze rozwiązanie
$array = [System.Collections.Generic.List[PSObject]]::New()
foreach ($user in $userList) {
    $array.add([PSCustomObject]@{
        Username = $user.Name
        Email = $user.SamAccountName
    })
}
#endregion good
