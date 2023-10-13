# Konwersja tablicy hash na obiekt PSObject

function ConvertTo-PsObject($hashtable)
{
   $object = New-Object PSObject
   $hashtable.GetEnumerator() |
      ForEach-Object { Add-Member -inputObject $object `
	  	-memberType NoteProperty -name $_.Name -value $_.Value }
   $object
}

$hash = @{Imie='Kazik'; Wiek=25; Status='Student'}
$hash
ConvertTo-PsObject $hash
