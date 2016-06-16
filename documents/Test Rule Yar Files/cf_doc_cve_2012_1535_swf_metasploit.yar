
rule cf_doc_cve_2012_1535_swf_metasploit
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		maltype = "all"
		filetype = "doc"
		yaraexchange = "No distribution without author's consent"
		comment = "Detects SWF exploiting CVE-2012-1535 (OTF)"
		version = "v0.2"
		ref0 = "https://www.adobe.com/support/security/bulletins/apsb12-18.html"
		ref1 = "http://www.metasploit.com/modules/exploit/windows/browser/adobe_flash_otf_font"
		date = "2013-04"
	strings:
		$FWS = { 46 57 53 }
		$font = "PSpop"
		$sc_func = "hexToBin"
		$func = "heapSpray"
		$font_func0 = "FontAsset"
		$font_func1 = "createTextLine"
		$s1 = "Edit the world in hex"
	condition:
		$FWS at 0 and $font and $s1 and $sc_func and $func and 1 of ($font_func*)
}
