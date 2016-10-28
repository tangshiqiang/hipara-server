import base64
import json
import urllib
import requests
from django.conf import settings
#
host_url = settings.GRR_HOST_URL
USER_NAME = settings.GRR_USER_NAME
PASSWORD = settings.GRR_USER_PASSWORD

# Generate Auth Headers and Cookie
def gen_auth_headers():
	"""
	Fucntion to generate http request headers and cookie
	:return: tupple - Header content and coockie from the request
	"""
	# Get CSRF Auth Header
	b64bytes = (base64.encodestring(str.encode('%s:%s' % (USER_NAME, PASSWORD)))).replace(b'\n', b'')
	auth_header = "Basic %s" % b64bytes.decode("utf-8")
	auth_req = requests.get(host_url, auth=(USER_NAME, PASSWORD))
	cookies = auth_req.cookies
	csrf_token = auth_req.cookies.get("csrftoken")
	headers = {
		"Authorization": auth_header,
		"x-csrftoken": csrf_token,
		"x-requested-with": "XMLHttpRequest"
	}

	return (headers, cookies)


# Find client URN
def get_client_urn(host):
	"""
	Function accesses the GRR API to retreive the client ID (urn)
	:param host: The host model object
	:return: string - the URN (GRR Client ID) or None.
	"""

	# Add values of host into query
	query = "query=%s" % (urllib.parse.quote_plus(host.name))

	if host.hardware_sn:
		query += "&query=%s" % (urllib.parse.quote_plus(host.hardware_sn))

	for interface in host.interfaces.all():
		if interface.mac:
			query += "&query=%s" % (urllib.parse.quote_plus(interface.mac))
		if interface.ipv4:
			query += "&query=%s" % (urllib.parse.quote_plus(interface.ipv4))
		if interface.ipv6:
			query += "&query=%s" % (urllib.parse.quote_plus(interface.ipv6))

	# Query the API
	r = requests.get(host_url + '/api/clients?' + query, auth=(USER_NAME, PASSWORD))
	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				js = json.loads(line)
				items = js.get('items', [])
				if items and len(items) == 1:
					item = items[0].get('value', {})
					urn = item.get('urn', {}).get('value')
					rtn = urn.split('aff4:/')[1] if 'aff4:/' in urn else None
			except ValueError:
				pass
	return rtn


# Get file
def get_file(host_urn, file_path):
	"""
	Funcion access the GRR API to start a flow on retrieving a file from a specified client
	:param host_urn: String - The GRR Client ID. Ex: C.1000000000000000
	:param file_path: String - The full file path of the file you wish GRR to retrieve
	:return: String - A GRR flow path: Ex: aff4:/C.1000000000000000/flows/F:ABCDEF12 or None
	"""

	# Get CSRF Auth Header
	headers, cookies = gen_auth_headers()

	data = {"hostname": host_urn, "paths": [file_path]}

	r = requests.post(host_url + "/api/robot-actions/get-files", cookies=cookies, headers=headers,
					  data=json.dumps(data))

	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				js = json.loads(line)
				operation_id = js.get('operation_id', None)
				rtn = operation_id
			except ValueError:
				pass
	return rtn


# Check Get File Flow
def get_file_status(operation_id):
	"""
	Function to check if the get file operation has completed
	:param operation_id: String - A GRR flow path: Ex: aff4:/C.1000000000000000/flows/F:ABCDEF12
	:return: Dictionary - Contains key value pairs containing the grr output,
	"""
	r = requests.get(host_url + "/api/robot-actions/get-files/" + operation_id, auth=(USER_NAME, PASSWORD))
	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				js = json.loads(line)
				state = js.get('state')
				result_count = js.get('result_count')
				file_found = result_count > 0

				if state == "RUNNING":
					rtn = {'complete': False, 'file_found': file_found, 'data': js}
				else:
					rtn = {'complete': True, 'file_found': file_found, 'data': js}
			except ValueError:
				pass

	return rtn


def operation_to_flow(operation_id):
	"""
	Function Converts an operation id to a flow id
	:param operation_id: String - A GRR flow path: Ex: aff4:/C.1000000000000000/flows/F:ABCDEF12
	:return: String - Flow ID Ex: F:ABCDEF12 or None
	"""
	if 'flows/F:' in operation_id and 'aff4:/' in operation_id:
		return operation_id.split('flows/')[1]
	return None


def download_file(client_id, flow_id):
	"""
	Function to download a file from a GRR flow.
	:param client_id: The GRR Client ID. Ex: C.1000000000000000
	:param flow_id: The GRR flow ID. EX: F:ABCDEF12
	:return: Zip Archive file or None
	"""
	archive_url = "/api/clients/%s/flows/%s/results/files-archive" % (client_id, flow_id)
	r = requests.get(host_url + archive_url, auth=(USER_NAME, PASSWORD))
	rtn = None
	if r.status_code == 200:
		rtn = r.text
	return rtn


# Get memory
def get_memory(client_id):
	"""
	Function to issue a GRR memory flow
	:param client_id: String - The GRR Client ID. Ex: C.1000000000000000
	:return: String - Flow ID returned from GRR or None
	"""

	# Get CSRF Auth Header
	headers, cookies = gen_auth_headers()

	data = {
		"flow": {
			"runner_args": {"flow_name": "MemoryCollector", "priority": "HIGH_PRIORITY"},
			"args": {"store_results_in_aff4": True}
		}
	}
	url = host_url + "/api/clients/%s/flows" % client_id
	r = requests.post(url, cookies=cookies, headers=headers, data=json.dumps(data))

	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				if "flow_id" in line:
					js = json.loads(line)
					val = js.get("value", {})
					flow_id = val.get('flow_id')
					rtn = flow_id
			except ValueError:
				pass
	return rtn


# Get running processes
def get_processes(client_id):
	"""
	Function to issue a GRR process flow
	:param client_id: String - The GRR Client ID. Ex: C.1000000000000000
	:return: String - Flow ID returned from GRR or None
	"""

	# Get CSRF Auth Header
	headers, cookies = gen_auth_headers()

	data = {"flow": {"runner_args": {"flow_name": "ListProcesses", "priority": "HIGH_PRIORITY"},
		"args": {"connection_states": [], "fetch_binaries": True}}}
	url = host_url + "/api/clients/%s/flows" % client_id
	r = requests.post(url, cookies=cookies, headers=headers, data=json.dumps(data))

	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				if "flow_id" in line:
					js = json.loads(line)
					val = js.get("value", {})
					flow_id = val.get('flow_id')
					rtn = flow_id
			except ValueError:
				pass
	return rtn


# Get Netstat
def get_netstat(client_id):
	"""
	Function to issue a GRR netstat flow
	:param client_id: String - The GRR Client ID. Ex: C.1000000000000000
	:return: String - Flow ID returned from GRR or None
	"""

	# Get CSRF Auth Header
	headers, cookies = gen_auth_headers()

	data = {"flow": {"runner_args": {"flow_name": "Netstat", "priority": "HIGH_PRIORITY"}, "args": {}}}
	url = host_url + "/api/clients/%s/flows" % client_id
	r = requests.post(url, cookies=cookies, headers=headers, data=json.dumps(data))

	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				if "flow_id" in line:
					js = json.loads(line)
					val = js.get("value", {})
					flow_id = val.get('flow_id')
					rtn = flow_id
			except ValueError:
				pass
	return rtn


# Get logs
def get_windows_logs(client_id):
	"""
	Function to issue a GRR get logs flow for windows
	:param client_id: String - The GRR Client ID. Ex: C.1000000000000000
	:return: String - Flow ID returned from GRR or None
	"""

	# Get CSRF Auth Header
	headers, cookies = gen_auth_headers()

	data = {
		"flow": {
			"runner_args": {"flow_name": "ArtifactCollectorFlow", "priority": "HIGH_PRIORITY"},
			"args": {
				"artifact_list": [
					"WindowsXMLEventLogApplication",
					"WindowsEventLogSecurity",
					"WindowsEventLogs",
					"WindowsEventLogApplication",
					"WindowsEventLogSystem"
				],
				"store_results_in_aff4": True
			}
		}
	}
	url = host_url + "/api/clients/%s/flows" % client_id
	r = requests.post(url, cookies=cookies, headers=headers, data=json.dumps(data))

	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				if "flow_id" in line:
					js = json.loads(line)
					val = js.get("value", {})
					flow_id = val.get('flow_id')
					rtn = flow_id
			except ValueError:
				pass
	return rtn


def get_linux_logs(client_id):
	"""
	Function to issue a GRR get logs flow for linux
	:param client_id: String - The GRR Client ID. Ex: C.1000000000000000
	:return: String - Flow ID returned from GRR or None
	"""
	# Get CSRF Auth Header
	headers, cookies = gen_auth_headers()

	data = {
		"flow": {
			"runner_args": {"flow_name": "ArtifactCollectorFlow", "priority": "HIGH_PRIORITY"},
			"args": {
				"artifact_list": [
					"LinuxAuditLogs",
					"LinuxAuthLogs",
					"LinuxCronLogs"
				],
				"store_results_in_aff4": True
			}
		}
	}
	url = host_url + "/api/clients/%s/flows" % client_id
	r = requests.post(url, cookies=cookies, headers=headers, data=json.dumps(data))

	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				if "flow_id" in line:
					js = json.loads(line)
					val = js.get("value", {})
					flow_id = val.get('flow_id')
					rtn = flow_id
			except ValueError:
				pass
	return rtn


def get_osx_logs(client_id):
	"""
	Function to issue a GRR get logs flow for osx
	:param client_id: String - The GRR Client ID. Ex: C.1000000000000000
	:return: String - Flow ID returned from GRR or None
	"""
	# Get CSRF Auth Header
	headers, cookies = gen_auth_headers()

	data = {
		"flow": {
			"runner_args": {"flow_name": "ArtifactCollectorFlow", "priority": "HIGH_PRIORITY"},
			"args": {
				"artifact_list": [
					"OSXAppleSystemLogs",
					"OSXAuditLogs",
					"OSXMiscLogs",
					"OSXSystemLogs",
					"OSXUserApplicationLogs"
				],
				"store_results_in_aff4": True
			}
		}
	}
	url = host_url + "/api/clients/%s/flows" % client_id
	r = requests.post(url, cookies=cookies, headers=headers, data=json.dumps(data))

	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				if "flow_id" in line:
					js = json.loads(line)
					val = js.get("value", {})
					flow_id = val.get('flow_id')
					rtn = flow_id
			except ValueError:
				pass
	return rtn


# Get host os version
def get_host_os(client_id):
	"""
	Function to retrieve the host OS version
	:param client_id: String - The GRR Client ID. Ex: C.1000000000000000
	:return: String - Windows, Linux, Darwin, or None
	"""
	# Query the API
	r = requests.get(host_url + '/api/clients/' + client_id, auth=(USER_NAME, PASSWORD))
	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				js = json.loads(line)
				val = js.get('value', {})
				if "os_info" in val:
					system = val.get("os_info", {}).get("value", {}).get("system", {})
					rtn = system.get("value")
			except ValueError:
				pass
	return rtn


# Recursive list directory
def update_fs_listing(client_id):
	"""
	Function to issue a GRR update virtual file system listing with a 5 level depth
	:param client_id: String - The GRR Client ID. Ex: C.1000000000000000
	:return: String - Flow ID returned from GRR or None
	"""
	# Get CSRF Auth Header
	headers, cookies = gen_auth_headers()

	data = {"file_path": "fs/os", "max_depth": 5, "notify_user": False}
	url = host_url + "/api/clients/%s/vfs-refresh-operations" % client_id
	r = requests.post(url, cookies=cookies, headers=headers, data=json.dumps(data))

	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				if "operation_id" in line:
					js = json.loads(line)
					operation_id = js.get("operation_id", {})
					flow_id = operation_to_flow(operation_id)
					rtn = flow_id
			except ValueError:
				pass
	return rtn


def download_fs_timeline(client_id):
	"""
	Function to download the virtual file system timeline in CSV output
	:param client_id: String - The GRR Client ID. Ex: C.1000000000000000
	:return: CSV file or None
	"""
	r = requests.get(host_url + '/api/clients/%s/vfs-timeline-csv/fs/os' % client_id, auth=(USER_NAME, PASSWORD))
	rtn = None
	if r.status_code == 200:
		rtn = r.text
	return rtn


# Get system registry
def get_windows_registry(client_id):
	"""
	Function to issue a GRR get windows registry flow
	:param client_id: String - The GRR Client ID. Ex: C.1000000000000000
	:return: String - Flow ID returned from GRR or None
	"""
	# Get CSRF Auth Header
	headers, cookies = gen_auth_headers()

	data = {
		"flow": {
			"runner_args": {"flow_name": "ArtifactCollectorFlow", "priority": "HIGH_PRIORITY"},
			"args": {
				"artifact_list": [
					"WindowsPersistenceRegistryKeys",
					"WindowsRegistryCurrentControlSet",
					"WindowsRegistryProfiles",
					"WindowsShellHandlersRegistryKeys",
					"WindowsSystemRegistryFiles",
					"WindowsUserRegistryFiles"
				],
				"store_results_in_aff4": True
			}
		}
	}
	url = host_url + "/api/clients/%s/flows" % client_id
	r = requests.post(url, cookies=cookies, headers=headers, data=json.dumps(data))

	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				if "flow_id" in line:
					js = json.loads(line)
					val = js.get("value", {})
					flow_id = val.get('flow_id')
					rtn = flow_id
			except ValueError:
				pass
	return rtn


# Get scheduled tasks
def get_windows_scheduled_tasks(client_id):
	"""
	Function to issue a GRR get scheduled tasks flow for windows
	:param client_id: String - The GRR Client ID. Ex: C.1000000000000000
	:return: String - Flow ID returned from GRR or None
	"""
	# Get CSRF Auth Header
	headers, cookies = gen_auth_headers()

	data = {
		"flow": {
			"runner_args": {"flow_name": "ArtifactCollectorFlow", "priority": "HIGH_PRIORITY"},
			"args": {
				"artifact_list": [
					"WindowsScheduledTasks",
					"WindowsSharedTaskScheduler"
				],
				"store_results_in_aff4": True
			}
		}
	}
	url = host_url + "/api/clients/%s/flows" % client_id
	r = requests.post(url, cookies=cookies, headers=headers, data=json.dumps(data))

	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				if "flow_id" in line:
					js = json.loads(line)
					val = js.get("value", {})
					flow_id = val.get('flow_id')
					rtn = flow_id
			except ValueError:
				pass
	return rtn


# Cancel Flow
def cancel_flow(client_id, flow_id):
	"""
	Function to cancel a flow from GRR
	:param client_id: String - The GRR Client ID. Ex: C.1000000000000000
	:param flow_id: String - The GRR flow ID. EX: F:ABCDEF12
	:return: Boolean or None
	"""
	# Get CSRF Auth Header
	headers, cookies = gen_auth_headers()

	url = host_url + "/api/clients/%s/flows/%s/actions/cancel" % (client_id, flow_id)
	r = requests.post(url, cookies=cookies, headers=headers)

	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				if "status" in line:
					js = json.loads(line)
					val = js.get("status", {})
					if val == "OK":
						rtn = True
					else:
						rtn = False
			except ValueError:
				pass
	return rtn


# Flow Status
def get_flow_status(client_id, flow_id):
	"""
	Funciton to retrieve the state of a flow from GRR
	:param client_id: String - The GRR Client ID. Ex: C.1000000000000000
	:param flow_id: String - The GRR flow ID. EX: F:ABCDEF12
	:return: JSON - Dictionary containing completion and error status as well as error messages or None
	"""
	r = requests.get(host_url + '/api/clients/%s/flows/%s/' % (client_id, flow_id))
	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				js = json.loads(line)
				state = js.get('value', {}).get('state', {}).get('value')

				if state == "RUNNING":
					rtn = {'complete': False}

				elif state == "TERMINATED":
					rtn = {'complete': True, 'error': False}

				elif state == "ERROR":
					err_msg = js.get('value', {}).get('context', {}).get('value', {}).get('backtrace')
					rtn = {'complete': True, 'error': True, 'error_message': err_msg}

				elif state == "CLIENT_CRASHED":
					err_msg = js.get('value', {}).get('context', {}).get('value', {}).get('backtrace')
					rtn = {'complete': True, 'error': True, 'error_message': err_msg}

			except ValueError:
				pass

	return rtn


# Get GRR Version string
def get_grr_version():
	"""
	Function to get the version of GRR
	:return: String - The GRR server version
	"""
	# Get CSRF Auth Header
	headers, cookies = gen_auth_headers()

	r = requests.get(host_url + '/api/config', cookies=cookies, headers=headers)
	rtn = None
	if r.status_code == 200:
		for line in r.text.splitlines(True):
			try:
				js = json.loads(line)
				sec = js.get('sections')
				if sec:
					for i in sec:
						if i.get('value', {}).get('name', {}).get('value') == 'Source':
							for o in i.get('value').get('options'):
								if o.get('value').get('name').get('value') == 'Source.version_string':
									return o.get('value').get('value').get('value')
			except ValueError:
				pass


# Get client binary
def get_client_binary(os, platform, linux_type=None):
	"""
	Function to download the client binary for GRR
	:param os: String - must be "windows", "linux" or "darwin"
	:param platform: String - must be "i386" or "amd64"
	:param linux_type: String - optional - "deb" or "rpm"
	:return: Binary or None
	"""
	# Get CSRF Auth Header
	headers, cookies = gen_auth_headers()

	# get grr version
	gv = get_grr_version()

	# build binary url
	ext = None
	pre = 'grr'
	if os != "windows" and os != "linux" and os != "darwin":
		return None

	if platform != "amd64" and platform != "i386":
		return None

	if os == "windows":
		ext = "exe"
		pre = 'GRR'

	if os == "linux" and linux_type:
		if linux_type == "deb" or linux_type == "rpm":
			ext = linux_type

	if os == "darwin":
		ext = "pkg"

	binary_url = '/api/config/binaries/EXECUTABLE/%s/installers/%s_%s_%s.%s' % (os, pre, gv, platform, ext)

	r = requests.get(host_url + binary_url, cookies=cookies, headers=headers)
	rtn = None
	if r.status_code == 200:
		rtn = r.text
	return rtn