
rule cf_rtf_cve_2010_3333
{
meta:
		author = "Mila @ Deependresearch.org"
		maltype = "apt"
		filetype = "rtf"
		yaraexchange = "No distribution without author's consent"
		date = "2012-07"
		cve = "CVE_2010-3333"
	strings:
		$rtf = "{\\rt"  /* RTF specs */ nocase
		$a1 = "pFragments" nocase
		//$a20 = "\\shp " nocase
		//$a21 ="\\shp\\" nocase
		//$a22 = "\\sp\\" nocase
		//$a23 = "\\sp \\" nocase
	condition:
		$rtf in (0..4) and $a1 //and any of($a2*)
}
