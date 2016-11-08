import urllib

def url_decode(data):
	if data[-3:] == '%00':
		data = data[:-3]
	data =urllib.parse.unquote_plus(data)
	return data