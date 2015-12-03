
rule cf_rtf_actor_cve_2012_0158_tnauthor_john_doe
{
meta:
		author = "Mila @ Deependresearch.org"
		maltype = "apt"
		filetype = "rtf"
		yaraexchange = "No distribution without author's consent"        
		date = "2012-07"
	strings:
		$doe = { 07 74 6E 61 75 74 68 6F 72 20 4A 6F 68 6E 20 44 6F 65 7D } /* tnauthor John Doe}*/
	condition:
		$doe in (0..1024)
}

rule cf_pdf_flash_cve_2010_1297
{
meta:
		maltype = "all"
		filetype = "pdf"
		yaraexchange = "public content http://blog.xanda.org"  
		author = "xanda"
		cve = "CVE_2010_1297"
		ref ="http://blog.xanda.org/2010/06/11/yara-rule-for-cve-2010-1297"
		hide = true
		impact = 5
	strings:
		$unescape = "unescape" fullword nocase
		$shellcode = /%u[A-Fa-f0-9]{4}/$shellcode5 = /(%u[A-Fa-f0-9]{4}){5}/$cve20101297 = /\/Subtype ?\/Flash/
	condition:
		($unescape and $shellcode and $cve20101297) or ($shellcode5 and $cve20101297)
}

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

rule cf_doc_cve_2012_1535_original
{
	meta:
		author = "Mila @ deependresearch"
		maltype = "apt"
		filetype = "doc"
		yaraexchange = "No distribution without author's consent"
		date = "2012-08"
		description = "word document CVE-2012-1535"
		version = "1.0"
		type ="APT"
		md5 = "AD3AA76DD54F6BE847B927855BE16C61,7E3770351AED43FD6C5CAB8E06DC0300"
		reference = "http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2012-1535"
	strings:
		$a = { 53 00 69 00 6D 00 53 00 75 00 6E 00 } /*S.i.m.S.u.n*/
		$b = { 57 6F 72 64 2E 44 6F 63 75 6D 65 6E 74 2E 38 } /*Word.Document.8*/
		$c = { 4D 61 69 6E 2F 70 72 69 76 61 74 65 3A} /*Main/private:*/
		$d = { 66 6C 61 73 68 2E 64 69 73 70 6C 61 79 06 53 70 72 69 74 65 06 4F 62 6A 65 63 74 0F 45 76 65 6E 74 44 69 73 70 61 74 63 68 65 72 0D 44 69 73 70 6C 61 79 4F 62 6A 65 63 74 } /*flash.display.Sprite.Object.EventDispatcher.DisplayObject*/
		$e = { 68 69 6A 6B 6C 6D 6E 6F } /*hijklmno strings */
		$f = {45 78 61 6D 70 6C 65 0B 63 72 65 61 74 65 4C 69 6E 65 73 09 68 65 61 70 53 70 72 61 79 08 68 65 78 54 6F 42 69 6E 07 6D 78 2E 63 6F 72 65 0A 49 46 6C 65 78 41 73 73 65 74 09 46 6F 6E 74 41 73 73 65 74 0A 66 6C 61 73 68 2E 74 65 78 74 } /*Example.createLines.heapSpray.hexToBin.mx.core.IFlexAsset.FontAsset.flash.text*/
	condition:
		all of them
}

rule cf_pdf_CVE_2013_0640
{
		meta:
			description = "detects CVE_2013_0640, types known as of March 17,2013"
			reference = "http://blog.vulnhunt.com/index.php/2013/02/21/cve-2013-0641-analysis-of-acrobat-reader-sandbox-escape/"
			author = "Mila DeepEnd Research"
			cve = "cve-2013-0640"
			filetype = "pdf"
			note = "tested on 11K malicious and 10k clean pdfs"
			yaraexchange = "No distribution without author's consent"
	strings:
			$pdf1 = "%PDF" nocase
			$s1 = { 2F 58 46 41 20 }//xfa
			$s2 = { 2F 41 63 72 6F 46 6F 72 6D 20 }//acroform
			$s3 = { 2F 4F 70 65 6E 41 63 74 69 6F 6E }//openaction
			$s4 = { 2F 4E 65 65 64 73 52 65 6E 64 65 72 69 6E 67 20 74 72 75 65 } ///NeedsRendering true
	condition:
			$pdf1 in (0..1018) and all of ($s*)
}
/*CVE-2013-0640_PDF_0CDF55626E56FFBF1B198BEB4F6ED559_report.pdf2
CVE-2013-0640_PDF_151ADD98EEC006F532C635EA3FC205CE_action_plan.pdf_
CVE-2013-0640_PDF_2A42BF17393C3CAAA663A6D1DADE9C93_Mandiant.pdf_
CVE-2013-0640_PDF_3119ABBA449D16355CEB385FD778B525_mousikomi.pdf_
CVE-2013-0640_PDF_3668B018B4BB080D1875AEE346E3650A_action_plan.pdf_
CVE-2013-0640_PDF_37A9C45B78F4DEE9DA8FD8019F66005A_sample.pdf_
CVE-2013-0640_PDF_3F301758AA3D5D123A9DDBAD1890853B_EUAG_report.pdf_
CVE-2013-0640_PDF_6945E1FBEF586468A6D4F0C4F184AF8B_report.pdf_
CVE-2013-0640_PDF_7005E9EE9F673EDAD5130B3341BF5E5F_2013-Yilliq Noruz Bayram Merikisige Teklip.pdf_
CVE-2013-0640_PDF_701E3F3973E8A8A7FCEC5F8902ECBFD9_701E3F3973E8A8A7FCEC5F8902ECBFD9
CVE-2013-0640_PDF_88292D7181514FDA5390292D73DA28D4_ASEM_Seminar.pdf_
CVE-2013-0640_PDF_8E3B08A46502C5C4C45D3E47CEB38D5A_cc08_v143.pdf_
CVE-2013-0640_PDF_9C572606A22A756A1FCC76924570E92A_pdf.pdf_
CVE-2013-0640_PDF_A7C89D433F737B3FDC45B9FFBC947C4D_A7C89D433F737B3FDC45B9FFBC947C4D
CVE-2013-0640_PDF_AD668992E15806812DD9A1514CFC065B_arp.pdf_
CVE-2013-0640_PDF_AE52908370DCDF6C150B6E2AD3D8B11B_AE52908370DCDF6C150B6E2AD3D8B11B
CVE-2013-0640_PDF_AF061F8C63CD1D4AD83DC2BF81F36AF8_readme.pdf_
CVE-2013-0640_PDF_C03BCB0CDE62B3F45B4D772AB635E2B0_The 2013 Armenian Economic Association.pdf_
CVE-2013-0640_PDF_D00E4AC94F1E4FF67E0E0DFCF900C1A8_???.pdf_
CVE-2013-0640_PDF_EF90F2927421D61875751A7FE3C7A131_action_plan.pdf3
CVE-2013-0640_PDF_F3B9663A01A73C5ECA9D6B2A0519049E_Visaform Turkey.pdf_
*/

rule cf_pdf_CVE_2013_0640_original0day
{
		meta:
				description = "detects CVE_2013_0640, the original 0day type with the nfunction key"
				reference = "https://www.securelist.com/en/downloads/vlpdfs/themysteryofthepdf0-dayassemblermicrobackdoor.pdf"
				author = "Dewan Chowdhury"
				yaraexchange = "No distribution without author's consent"
		 	  tag = "Adobe Reader, CVE-2013-0640, CVE-2013-0641" 
	      comment = "Detects strings attributed to CVE-2013-0640, CVE-2013-0641" 
    strings: 
	       $pdf1  = "%PDF" nocase 
	       $s1  = "r+=ue" 
	       $s2  = "AcroForm" nocase 
	       $s3  = "nfunction" 
 		condition:
			$pdf1 in (0..1018) and all of ($s*)
}

/*CVE-2013-0640_PDF_2A42BF17393C3CAAA663A6D1DADE9C93_Mandiant.pdf_
CVE-2013-0640_PDF_3119ABBA449D16355CEB385FD778B525_mousikomi.pdf_
CVE-2013-0640_PDF_37A9C45B78F4DEE9DA8FD8019F66005A_sample.pdf_
CVE-2013-0640_PDF_AF061F8C63CD1D4AD83DC2BF81F36AF8_readme.pdf_
CVE-2013-0640_PDF_F3B9663A01A73C5ECA9D6B2A0519049E_Visaform Turkey.pdf_
*/

rule cf_pdf_CVE_2013_0640_uyghur_tibet
{
	meta:
			description = "detects CVE_2013_0640 variant desribed below"
	 		reference = "https://www.securelist.com/en/downloads/vlpdfs/themysteryofthepdf0-dayassemblermicrobackdoor.pdf"
			author = "Jaime Bblasco Alienvault"
			cve = "cve-2013-0640"
			filetype = "pdf"
			yaraexchange = "No distribution without author's consent"
	strings:
		$pdf  = "%PDF" nocase
		$comment = {3C 21 2D 2D 0D 0A 63 57 4B 51 6D 5A 6C 61 56 56 56 56 56 56 56 56 56 56 56 56 56 63 77 53 64 63 6A 4B 7A 38 35 6D 37 4A 56 6D 37 4A 46 78 6B 5A 6D 5A 6D 52 44 63 5A 58 41 73 6D 5A 6D 5A 7A 42 4A 31 79 73 2F 4F 0D 0A}
	condition:
		$pdf at 0 and $comment in (0..200)
}

/*CVE-2013-0640_PDF_7005E9EE9F673EDAD5130B3341BF5E5F_2013-Yilliq Noruz Bayram Merikisige Teklip.pdf_
CVE-2013-0640_PDF_8E3B08A46502C5C4C45D3E47CEB38D5A_cc08_v143.pdf_
CVE-2013-0640_PDF_AD668992E15806812DD9A1514CFC065B_arp.pdf_
CVE-2013-0640_PDF_D00E4AC94F1E4FF67E0E0DFCF900C1A8_???.pdf_
*/

rule cf_pdf_cve_2007_5659
{
	meta:
		maltype = "all"
		filetype = "pdf"
		yaraexchange = "No distribution without author's consent"
		author = "Michael Remen"
		source = "Yara Exchange"
		date = "2012-08"
		version = "1.0"
		description = "CVE-2007-5659"
	strings:
		$a = {255044462d}
		$b = {7961727073}
		$c = {6570616373656e75}  
		$d = {6e6f6974636e7566}              
		$e = {7961727241}
	condition:
		all of them
}

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

rule cf_rtf_cve_2012_0158_var1_objocx
{
	meta:
		author = "Mila @ Deependresearch.org"
		maltype = "apt"
		filetype = "rtf"
		yaraexchange = "No distribution without author's consent"
		date = "2012-08"
		cve = "CVE-2012-0158"
	strings:
		$ofc = { D0 CF 11 E0 A1 B1 1A E1 }
		$rtf = "{\\rt"  /* RTF specs */ nocase
		$a1 = "\\object" nocase
		$a2 = "\\objemb" nocase
		$a3 = "\\objocx" nocase
	condition:
		($ofc or $rtf in (0..10)) and $a1 and ($a2 or $a3)
}

rule cf_rtf_cve_2012_1856
{
	meta:    
		maltype = "apt"
		filetype = "rtf"
		yaraexchange = "No distribution without author's consent"
		author = "Andrew Lyons"
		date = "2012-08"
		cve = "CVE-2012-1856"
		desc1 = "Rtf MS 12-060 Exploit"
		desc2 = "Vulnerability in Windows Common Controls Could Allow Remote Code Execution (2720573)"
		ref = "http://technet.microsoft.com/en-us/security/bulletin/ms12-060"
	strings:
		$header = "{\\rt"
		$objdata = /objdata[[:space:].]{1,20}01.{0,1}05.{0,1}00.{0,1}00.{0,1}02.{0,1}00.{0,1}00.{0,1}00/
		$objdataB = "}0105000002000000"
		$doc_asciiA = "D0CF11E0A1B11AE1" nocase
		$doc_asciiB = "D\x0a0\x0aC\x0aF" nocase
		$doc_asciiC = "0CF11E0A1B" nocase
		$clsid = "9665fb1e7c85d111b16a00c0f0283628" nocase
		$tabstrip = "MSComctlLib.TabStrip"
		$tabstrip_ascii = "4d53436f6d63746c4c69622e546162537472697" nocase
	condition:
		$header at 0 and ($objdata or $objdataB) and 1 of ($doc_asciiA,$doc_asciiB,$doc_asciiC) and 1 of ($clsid,$tabstrip,$tabstrip_ascii)
}

rule cf_rtf_cve_2010_3333_rare_ge_type
{
		meta:
		author = "Mila @ Deependresearch.org"
		maltype = "apt"
		filetype = "rtf"
		yaraexchange = "No distribution without author's consent"
		date = "2012-07"
		cve = "CVE_2010-3333"
		ref = "http://www.sophos.com/medialibrary/PDFs/technical%20papers/sophosrichtextformatmanipulationstpna.pdf"
	strings:
		$rarertf = "{\\ge"  /* RTF specs */ nocase
		$a1 = "pFragments" nocase
		$a20 = "\\shp " nocase
		$a21 ="\\shp\\" nocase
		$a22 = "\\sp\\" nocase
		$a23 = "\\sp \\" nocase
	condition:
		$rarertf in (0..4) and $a1 and any of($a2*)
}

rule cf_rtf_cve_2012_0158_var2_mscomctllib
{
	meta:
		author = "drobinson"
		maltype = "apt"
		filetype = "rtf"
		yaraexchange = "No distribution without author's consent"
		date = "2012-08"
		cve = "CVE-2012-0158"
	strings:
		$MSComctlLib   = "4D53436F6D63746C4C69622E" nocase
		$ListViewCtrl   = "4C697374566965774374726C" nocase
		$TreeViewCtrl   = "54726565566965774374726C" nocase
	condition:
		$MSComctlLib and ($ListViewCtrl or $TreeViewCtrl) 
}

rule cf_xdp_embedded_pdf
{
	meta:
		maltype = "apt"
		filetype = "xdp"
		yaraexchange = "No distribution without author's consent"             
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		date = "2012-08"
		ref = "http://blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp"
	strings:
		$s1 = "<pdf xmlns="
		$s2 = "<chunk>"
		$s3 = "</pdf>"
		$header0 = "%PDF"
		$header1 = "JVBERi0"
	condition:
		all of ($s*) and 1 of ($header*)
}

rule cf_pdf_actor_creationdate_eval
{
	meta:
		author = "Steve"
		description = "Various malicious PDF files"
		date = "2012-11-14"
		maltype = "any"
		filetype = "pdf"
		yaraexchange = "No distribution without author's consent"
	strings: 
		$pdf = "%PDF"
		$create_date = "/CreationDate (eval)"
	condition:
		all of them
}

//David Kovar The latest round of Blackhole 2 PDFs that I've been seeing look like this: /CreationDate %#^&*%^#@&%#@3J48481K3J443N4A4C29 That starts a blob that is decoded by a JS

rule CVE_2013_3893
{
	meta:
		author = "Brian Bartholomew iSIGHT Partners"
		maltype = "apt"
		yaraexchange = "No distribution without author's consent"
    		date = "09/20/2013"
    		descrption = "This rule will detect CVE-2013-3893"
    		reference_1 = "http://technet.microsoft.com/en-us/security/advisory/2887505"
		reference_2 = "http://blogs.technet.com/b/srd/archive/2013/09/17/cve-2013-3893-fix-it-workaround-available.aspx"
		status = "Tested against the one known live sample we were able to find and it works"
	
	strings:
		$String_1 = "onlosecapture" nocase
		$String_2 = "setCapture" nocase
		$String_3 = "CollectGarbage" nocase
	
	condition:
		all of them
}

rule cf_doc_dridex_macro {
	meta:
		description = "docs containing strings found in dridex droppers"
		reference = "https://www.virustotal.com/en/file/ee3109530d81ede253eb3dd8bfdac7afe1ee4a6ca833429f0114a4f74812afd9/analysis/"
		author = "@Matt_Anderson"
		yaraexchange = "No distribution without author's consent"
		date = "2015-04"
		filetype = "doc"
		md5 = "cb402edf28d70da6a9bbcffd9242bbd8"

	strings:
		$s1 = "To view this document, please turn on the Edit mode and Macroses!"
		$s2 = "Microsoft Office 2013"
		$s3 = "To display the contents of the document click on Enable Content button."
		$s4 = "Microsoft Office 2010"
		$s5 = "To display the contents of the document click on Enable Content button."
		$s6 = "Microsoft Office 2007"
		$s7 = "1. To display the contents of the document click on Options button."
		$s8 = "2. Then select Enable this content and click on OK button."
		$s9 = "Microsoft Office 2003"
		$s10 = "1. Go to Tools > Macro submenu and select Security."
		$s11 = "2. Select Low option and click on OK button."
		$s12 = "Unable to retrieve information from the bank. Please check your bank account."
		$s13 = "Attention! This document was created by"
		$s14 = "a newer version of Microsoft OfficeTM"
		$s15 = "Macros must be enabled to display the contents of the document."

	condition:
		uint32(0) == 0xE011CFD0 and 8 of them
}

rule cf_doc_cve_2012_1535_shellcode
{
	meta:
		author = "ned@shadowserver.org"
		maltype = "apt"
		filetype = "doc"
		yaraexchange = "No distribution without author's consent"
		date = "2012-08"
		type = "APT"
		version = "1.0"
		md5 = "b65d8b5b4205fd001398e873c32c4505,8b47310c168f22c72a263437f2d246d0,7e3770351aed43fd6c5cab8e06dc0300"
		description = "Heap spray shellcode used in CVE-2012-1535 exploits"
	strings:
		$shellcode ="9090909090E947010000C28F36D8A0DF16D5B5F0DE78D00589E91B28BF56BEF71ED697165FFAA1665256D0541988A5D913E98E3A172B9BB28253A2E362577E574F52444C2E746D7000"
	condition:
		$shellcode
}

rule cf_rtf_cve_2012_0158_var3_fchars
{
		meta:
			author = "Michael Remen"
			maltype = "apt"
			filetype = "rtf"
			yaraexchange = "No distribution without author's consent"
			date = "2012-8"
			cve = "CVE-2012-0158"
		strings:
			$a = {7B 5C 72 74}
			$b = /(\\\'[a-f0-9]{2}){30}/
			$c = {5c2a5c666368617273}                
		condition:
			all of them
}

