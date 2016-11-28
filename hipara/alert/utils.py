import urllib

def url_decode(data):
	try:
		if data[-3:] == '%00':
			data = data[:-3]
	except Exception:
		pass

	try:
		data =urllib.parse.unquote_plus(data)
	except Exception:
		pass
	return data