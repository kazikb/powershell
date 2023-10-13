# Algorytm wykorzystujący mechanizm Jobów aby równolegle uruchamiać zadeklarowaną liczbę zadań.
# W momencie jak zadanie jest kończone to w jego miejsce wskakuje kolejne aż wszystkie się wykonają (przy zachowaniu limitu równolegle uruchomionych).

$list = 1,2,3,4,5,6,7,8,9,10
$script = {
    param($job_x)
    Start-Sleep -Seconds (5*$job_x)
}
$njobs = 4


foreach ($x in $list) {
    $running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
    if ($running.Count -le $njobs) {
        Write-Host "Start job $x"
        Start-Job -ScriptBlock $script -ArgumentList $x
        Start-Sleep -Seconds 1
    }

    while ($true) {
        $running = @(Get-Job | Where-Object { $_.State -eq 'Running' })
        Write-Host "Nr jobs: $($running.Count)"
        if ($running.Count -eq $njobs) {
            Start-Sleep -Seconds 5
        } else {
            Get-Job | Where-Object { $_.State -eq 'Completed' } | Remove-Job
            Write-Host "Job Completed"
            Break
        }
    }
}
Get-Job | Wait-Job
Get-Job | Remove-Job
