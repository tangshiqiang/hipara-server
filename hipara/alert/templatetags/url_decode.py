from alert.utils import url_decode as ud
from django import template

def url_decode(value):
	return ud(value)

register = template.Library()
register.filter('url_decode', url_decode)