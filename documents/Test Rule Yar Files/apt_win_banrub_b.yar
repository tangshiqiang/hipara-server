rule apt_win_banrub_b
{
meta:
	author = "Wes Hurd"
	example = "3e5de85ee9dfa4b1d771ad3e13ee707c"
	reference = "http://www.drwebhk.com/en/virus_techinfo/Trojan.DownLoader6.36657.html"
	yaraexchange = "No distribution without author's consent."
strings:
	$callback = "/art/porth.asp"
	$callback2 = "/li/htp.asp"
	$d = "dsfhkjwehjfwhqrjk"
	$LO = "LOOK PRO FINISH" wide
	$p = "Pass:%s Hostname:%s Ip:%s Os:%s Proxy:%s Vm:%s Pro"
	$u = "unistal"
	$XOR_URL = "lppt>++"
condition:
	3 of them
}
/*Banrub.B_16905AF750740310C8DF8AF332D2DE06
Banrub.B_1C592AB73593539B13024920561A9A9E
Banrub.B_34D93AE3AAE3DAACC84CC57A690C04C5
Banrub.B_3E5DE85EE9DFA4B1D771AD3E13EE707C
Banrub.B_4C5DADF854F38AC9E5717921F92104D1
Banrub.B_5EEE15CD02E1EC883AED17480869A82F
Banrub.B_81CC617619A7DB08335DD28E87FC930E.dll
Banrub.B_C67A02147BDABBAF171182A22E96CB6E
Banrub.B_EB952D6F02FBC1851F53DF7F0AFA977F
Banrub.B_FFBF53E72BC948F55EB095C1B3C82F3F
*/