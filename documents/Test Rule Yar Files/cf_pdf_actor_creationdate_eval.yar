
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
