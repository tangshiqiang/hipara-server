
rule CommentTeam_Grade2
{
	meta:
		author = "Michael Matonis (@matonis)"
		source = "Yara Exchange"
		date = "2013/02/12"
		comment = "Comment Team - Embedded Commands and Obfuscated Binaries in xcnt, xtit, xcd parameters"
		version = "1.0"
	strings:
		/*Stage 1 Directives*/
		$stage_one1 = "geturl:" nocase
		$stage_one2 = "sleep:" nocase
		$stage_one3 = "download:" nocase
		$stage_one4 = "allcomputer" nocase
		$stage_one5 = "content=" nocase

		/*Stage 2 Directives*/
		$stage_two0 = "upfile" nocase
		$stage_two2 = "postvalue" nocase
		$stage_two3 = "postfile" nocase
		$stage_two6 = "reqpath" nocase
		$stage_two7 = "savepath" nocase
		$stage_two10 = "reqfilepath" nocase
		$stage_two11 = "reqfile" nocase
		$stage_two13 = "postdata" nocase

		/*HTML Tags*/
		$html0 = "xcd=" nocase
		$html1 = "xtit=" nocase
		$html2 = "xcnt=" nocase
		$html3 = "<meta" nocase

		/*Other Elements*/
		$el0 = "atoi" nocase
		
	condition:
		(all of ($html*)) or (4 of ($stage_one*) and $el0) or (5 of ($stage_two*) and $el0)
}