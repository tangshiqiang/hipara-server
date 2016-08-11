
rule crime_cridex_memory
{
  meta:
    author = "Greg Leah"
    date  = "2013.03.11"
    description = "detects unpacked/memdumped Cridex/Bugat samples"
     yaraexchange = "No distribution without author's consent"
  strings:
    $ = "httpshots"
    $ = "httpinjects"
    $ = "formgrabber"
    $ = "bconnect"
  condition:
    all of them
}

rule crime_cridex_dump2
{
    meta:
    author      = "Tal Darsan"
    description = "Cridex detection rules, can be used on dump/sandox output"
     yaraexchange = "No distribution without author's consent"
   strings: 
        $file = /C:\\.*KB[0-9]{8}\.exe/
        $mutex = /Local\\XMR1B930[0-9A-F]{3}/
   condition:
        $file or $mutex
}
