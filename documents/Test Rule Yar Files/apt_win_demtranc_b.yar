
rule apt_win_demtranc_b
{ 
	meta: 
		author = "Diocyde"
		source = "ONA"
		date = "2012-11"
		version = "1.0"
		maltype = "apt"
		filetype = "pe"
		yaraexchange = "No distribution without author's consent"
		description = "APT: backdoor Demtranc.B" 
		reference1 = "http://operationona.wordpress.com/snowflake-collection/" 
		reference2 = "286D8F498826310CF74836ACAD8F7989"
	strings: 
		$var1 = "ST_START" ascii
		$var2 = "IDI_ICON_BLADE" wide
		$var3 = "main::InitHostInfo: " ascii
		$var4 = "inet::INET_cache: " ascii
		$var5 = "AWEXT32::" ascii
		$var6 = "main::dosrt:" ascii
		$var7 = "main::Daemon: Ready!" ascii
		$var8 = "Windows Update AutoUpdate Client" wide
	condition: 
		all of them 
}