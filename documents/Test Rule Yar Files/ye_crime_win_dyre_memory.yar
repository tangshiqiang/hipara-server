rule crime_win_dyre_memory
{
	meta:
		author = "blevene@salesforce.com"

		description = "Detects the configuration Dyre (AKA Dyreze/Dyzap) trojan injected into memory (explorer.exe memory space)"

		reference = "http://phishme.com/project-dyre-new-rat-slurps-bank-credentials-bypasses-ssl/"

		date = "2014-09-04"
		yaraexchange = "No distribution without author's consent"
		type = "Win32 PE"

	strings:
		$s1 = "serverlist"
		$s2 = "srv_"

		$s3 = "litem"
		$s4 = "<sal>"
	condition:
		all of them

}
 
/*
0d5ad9759753cb4639cd405eddbe2a16

*/
