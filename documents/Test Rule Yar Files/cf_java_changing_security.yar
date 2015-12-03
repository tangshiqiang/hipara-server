
rule cf_java_changing_security
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://docs.oracle.com"
		maltype = "all"
		filetype = "jar"
		yaraexchange = "No distribution without author's consent"
		date = "2012-09"
	strings:
		$magic = { CA FE BA BE }
		/* Modifying local security : a class that allows applications to implement a security policy */
		$manager = /[sg]etSecurityManager/
		$sec0 = "PrivilegedActionException"
		$sec1 = "AccessController.doPrivileged"
		$sec2 = "AllPermission"
		$sec3 = "ProtectionDomain"
		$gen1 = "file://"
	condition:
		$magic at 0 and $manager and 2 of ($sec*) and $gen1
}
