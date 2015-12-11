
rule cf_java_execute_write
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
		/* Local execution */
		$exec0 = "Runtime.getRuntime"
		$exec1 = "exec"
		/* Exploit */
		$exp0 = /arrayOf(Byte|String)/
		$exp1 = "toByteArray"
		$exp2 = "HexDecode"
		$exp3 = "StringtoBytes"
		$exp6 = "InputStream"
		$exp7 = "Exception.printStackTrace"
		$fwrite0 = "FileOutputStream" /*contains a byte stream with the serialized representation of an object given to its constructor*/
		$fwrite3 = "MarshalledObject"
		$fwrite4 = "writeObject"
		$fwrite5 = "OutputStreamWriter"
		/* Loader indicators */
		$load0 = "getResourceAsStream"
		$load1 = /l(port|host)/
		$load2 = "ObjectInputStream"
		$load3 = "ArrayOfByte"
				//$gen1 = "file://"
	condition:
		$magic at 0 and ((all of ($exec*) and 2 of ($fwrite*)) or (2 of ($exp*) and 2 of ($load*)))
}
