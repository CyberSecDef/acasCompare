[CmdletBinding()] 
    param (
        [Parameter(Mandatory=$true, ValueFromPipeline, ValueFromPipelineByPropertyName)][string]$Analysis,
		[Parameter(Mandatory=$true, ValueFromPipeline, ValueFromPipelineByPropertyName)][string]$scanPath,
		[Parameter(Mandatory=$true, ValueFromPipeline, ValueFromPipelineByPropertyName)][string]$outputFormat,
		[Parameter(Mandatory=$false, ValueFromPipeline, ValueFromPipelineByPropertyName)][switch]$showAll
    )
#.\acasCompare.ps1 -Analysis '.\Vulnerabilitiy Analysis.csv' -scanPath 'C:\Users\robert.weber.reg\Downloads\ACAS\' -outputFormat Screen


Begin{
	clear;
	$error.clear();
	Class acasCompare{
		$analysis
		$scanPath
		$outputFormat
		$showAll
		$scanSummary = @()
		
		acasCompare($analysis, $scanPath, $outputFormat, $showAll){
			$this.analysis     = $analysis
			$this.scanPath     = $scanPath
			$this.outputFormat = $outputFormat
			$this.showAll      = $showAll
		}
		
		execute(){
			Write-Progress -Activity 'Comparing ACAS Scans to Repository' -Status "1 / 3 : Parsing Scans Results" -PercentComplete (0/3*100) -id 1
			$this.parseScans()
			Write-Progress -Activity 'Comparing ACAS Scans to Repository' -Status "2 / 3 : Parsing Repository Results" -PercentComplete (1/3*100) -id 1
			$this.parseAnalysis()
			Write-Progress -Activity 'Comparing ACAS Scans to Repository' -Status "3 / 3 : Generating Report" -PercentComplete (2/3*100) -id 1
			$this.getReport()
		}
		
		parseAnalysis(){
			
			$summaries = import-csv $this.analysis
			$index = 0
			Write-Progress -Activity 'Parsing ACAS Summaries' -Status "$($index) / $($summaries.count) : Parsing Summaries" -PercentComplete ($index/$($summaries.count)*100) -id 2 -parentId 1
			foreach($summary in $summaries){
				$index++
				Write-Progress -Activity 'Parsing ACAS Summaries' -Status "$($index) / $($summaries.count) : Parsing Summaries" -PercentComplete ($index/$($summaries.count)*100) -id 2 -parentId 1
				$this.scanSummary += [pscustomObject]@{
					'Scan' = 'Security Center';
					'Hostname' = $summary.'DNS Name';
					'IP' = $summary.'IP Address';
					'Start' = 0;
					'OS' = $summary.'OS CPE';
					# 'Info' = $summary.'Info';
					'Low' = $summary.Low
					'Med' = $summary.'Med.';
					'High' = $summary.High;
					'Crit' = $summary.'Crit.';
				}
			}
			Write-Progress -Activity 'Parsing ACAS Summaries' -Status "$($index) / $($summaries.count) : Parsing Summaries" -PercentComplete 100 -Completed -id 2 -parentId 1
		}
		
		parseScans(){
			$activeScans = gci -path $this.scanPath -filter "*.nessus"

			$index = 0
			Write-Progress -Activity 'Parsing Scan Results' -Status "$($index) / $($activeScans.count) : Parsing Scan" -PercentComplete ($index/$($activeScans.count)*100) -id 2 -parentId 1
			foreach($scan in ($activeScans | sort { $_.length })){
				$index++
				Write-Progress -Activity 'Parsing Scan Results' -Status "$($index) / $($activeScans.count) : Parsing Scan $($scan.fullName)" -PercentComplete ($index/$($activeScans.count)*100) -id 2 -parentId 1
				
				$scanData = [xml](gc $scan.fullname)
				foreach($h in ($scanData.selectNodes("//ReportHost"))){
					$this.scanSummary += [pscustomObject]@{
						'Scan' = $scan.name
						'Hostname' = $h.selectSingleNode("/NessusClientData_v2/Report/ReportHost[@name='$($h.name)']/HostProperties/tag[@name='host-fqdn']").'#text';
						'IP' = $h.selectSingleNode("/NessusClientData_v2/Report/ReportHost[@name='$($h.name)']/HostProperties/tag[@name='host-ip']").'#text';
						'Start' = $h.selectSingleNode("/NessusClientData_v2/Report/ReportHost[@name='$($h.name)']/HostProperties/tag[@name='HOST_START_TIMESTAMP']").'#text';
						'OS' = $h.selectSingleNode("/NessusClientData_v2/Report/ReportHost[@name='$($h.name)']/HostProperties/tag[@name='operating-system']").'#text';
						'Cred' = $h.selectSingleNode("/NessusClientData_v2/Report/ReportHost[@name='$($h.name)']/HostProperties/tag[@name='Credentialed_Scan']").'#text';
						'Low' = ($h.selectNodes("/NessusClientData_v2/Report/ReportHost[@name='$($h.name)']/ReportItem[@severity='1']")).count;
						'Med' = ($h.selectNodes("/NessusClientData_v2/Report/ReportHost[@name='$($h.name)']/ReportItem[@severity='2']")).count;
						'High' = ($h.selectNodes("/NessusClientData_v2/Report/ReportHost[@name='$($h.name)']/ReportItem[@severity='3']")).count;
						'Crit' = ($h.selectNodes("/NessusClientData_v2/Report/ReportHost[@name='$($h.name)']/ReportItem[@severity='4']")).count;
					}
				}
			}
			Write-Progress -Activity 'Parsing Scan Results' -Status "$($index) / $($activeScans.count) : Parsing Scan $($scan.fullName)" -Completed -PercentComplete 100 -id 2 -parentId 1
		}
		getReport(){
			$results = @()
			$index = 0;
			$summaries =  $this.scanSummary | ? { $_.scan -eq 'Security Center' } | sort { $_.Hostname, $_.start } -unique
			
			Write-Progress -Activity 'Generator Report' -Status "$($index) / $($summaries.count) : Adding Host" -PercentComplete 0 -id 2 -parentId 1
			$summaries | %{
				$index++
				Write-Progress -Activity 'Generator Report' -Status "$($index) / $($summaries.count) : Adding Host $($_.hostname)" -PercentComplete ($index/$($summaries.count)*100) -id 2 -parentId 1
				$sum = $_
				$scanResult = $this.scanSummary | ? { $_.scan -ne 'Security Center' -and $_.hostname -eq $sum.hostname } | sort -descending {$_.start} | select -first 1
				
				$sumScore = ([int]$sum.low*1 + [int]$sum.med*3 + [int]$sum.high*10 + [int]$sum.crit*10)
				if($sumScore -lt 1){$sumScore = 1}
				
				$scanScore = ([int]$scanResult.low*1 + [int]$scanResult.med*3 + [int]$scanResult.high*10 + [int]$scanResult.crit*10)
				
				$results += [pscustomObject]@{
					'Hostname' = $_.hostname;
					'IP' = $_.IP;
					'ACAS Low' = $_.Low
					'ACAS Med' = $_.Med
					'ACAS High' = $_.high
					'ACAS Crit' = $_.Crit
					'ACAS Score' = $sumScore
					'Score Diff' = [Math]::abs( $sumScore - $scanScore)
					
					'Score Percent Error' = [Math]::round( (($sumScore - $scanScore) / ($sumScore) * 100)  ,2)
					
					'Scan Score' = $scanScore
					'Scan Credentialed' = $scanResult.Cred
					'Scan Low' = $scanResult.Low
					'Scan Med' = $scanResult.Med
					'Scan High' = $scanResult.High
					'Scan Crit' = $scanResult.Crit
					'Scan Date' = (([System.DateTimeOffset]::FromUnixTimeSeconds($scanResult.Start)).DateTime).ToString("s")
					'Scan Name' = $scanResult.Scan
				}
				
			}
			
			Write-Progress -Activity 'Generator Report' -Status "$($index) / $($this.scanSummary.count) : Complete" -Completed -PercentComplete 100 -id 2 -parentId 1
			
			switch($this.outputFormat){
				"Screen" {
					$results | ? { $this.showAll -or ($_.'ACAS Score' -ne $_.'Scan Score' -and $_.'Scan Score' -ne 0)} | 
					select Hostname, IP, 
						'ACAS Low', 'ACAS Med', 'ACAS High', 'ACAS Crit', 
						'ACAS Score', 'Score Diff', 'Score Percent Error', 'Scan Score', 
						'Scan Credentialed',
						'Scan Low', 'Scan Med', 'Scan High', 'Scan Crit', 
						'Scan Date', 'Scan Name' | 
					ft -property Hostname, IP, 'ACAS Low', 'ACAS Med', 'ACAS High', 'ACAS Crit', 'ACAS Score', 'Score Diff', 'Score Percent Error', 'Scan Score', 'Scan Low', 'Scan Med', 'Scan High', 'Scan Crit', 'Scan Date', 'Scan Name' |
					out-string | 
					write-host
				}
				"CSV" {
					$results | ? { $this.showAll -or ($_.'ACAS Score' -ne $_.'Scan Score' -and $_.'Scan Score' -ne 0)} | 
					select Hostname, IP, 
						'ACAS Low', 'ACAS Med', 'ACAS High', 'ACAS Crit', 
						'ACAS Score', 'Score Diff', 'Score Percent Error', 'Scan Score', 
						'Scan Credentialed',
						'Scan Low', 'Scan Med', 'Scan High', 'Scan Crit', 
						'Scan Date', 'Scan Name' | 
						export-csv "acasCompare_$(get-date -format 'yyyyMMddHHmmss').csv" -noType
				
				}
			}
			
		}
	
	}
}
Process{
	$acas = [acasCompare]::new($analysis, $scanPath, $outputFormat, $showAll)
	$acas.execute()
}
End{

}
