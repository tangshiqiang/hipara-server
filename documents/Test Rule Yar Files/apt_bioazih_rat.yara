rule Bioazih_RAT {
	meta:
		description = "Bioazih RAT - http://goo.gl/MEyDBS"
		author = "Florian Roth"
		reference = "http://goo.gl/MEyDBS"
		date = "2015/04/24"
		hash1 = "1d6a8e97e674267c8a30d9cc9624a3f4d887eb9049123dcb5b3a8a2c2d08c943"
		hash2 = "39f158d1a501a3cda3978bf4285689a46a33fe710db9bb6a91520e68393f89e7"
		hash3 = "479ef7bcc179cae6b333b9ef97c3c2d6a0e65750a9b2f815431e23374a0f9b9b"
		hash4 = "dc580413758544f7f3d04a9465de3062c9d6ed4a11eaf36841735003b3be5594"
		score = 70
	strings:
		$z1 = "D:\\DevelopTool\\proxy\\900\\HttpSever\\Debug\\HttpSever.pdb" fullword ascii
		$z2 = "D:\\DevelopTool\\proxy\\900\\HttpSever\\HttpSever.cpp" fullword ascii
		$z3 = "Pass:%s Hostname:%s Ip:%s Os:%s Proxy:%s Vm:%s Pro:" fullword ascii
		$z4 = "http://jennifer998.lookin.at/ru/yy/htp.asp" fullword ascii
		$z5 = "Mozilla4.3 (compatible; MSIE 8.0; Windows NT 5.1)" fullword ascii

		$x1 = ".asp?keyword=" fullword ascii
		$x2 = "\\browseui.dll" fullword ascii
		$x3 = "FINISH  %d" fullword wide		
		$x4 = "Unknown OS" fullword wide
		$x5 = "bioazih" fullword ascii
		$x6 = "appmodul.cpp" fullword ascii			
		
		$s1 = "MFCO42uD.DLL" fullword ascii
		$s2 = "\\csrss.exe" fullword ascii
		$s3 = "\\cmd.exe" fullword ascii
		$s4 = "MFC42uD.DLL" fullword ascii
		$s5 = "MSVCRTD.dll" fullword ascii
		$s6 = "dsfhkjwehjfwhqrjk" fullword ascii
	condition:
		uint16(0) == 0x5A4D and filesize < 500KB and (
			( 1 of ($z*) and 2 of ($x*) ) or
			4 of ($x*) or
			2 of ($x*) and 4 of ($s*)
		)
}