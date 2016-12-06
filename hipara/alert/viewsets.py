from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
import json
import datetime
from .models import Alert, Host, Interface, LiveResponse, LiveResponseFlow
from .tasks import process_alert, cancel_lr, perform_lr
from .utils import url_decode
from .grr_utils import get_file_status, flow_to_operation, get_flow_result


class CsrfExemptSessionAuthentication(SessionAuthentication):
	def enforce_csrf(self, request):
		return

class LogsViewSet(viewsets.ViewSet):
	authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)

	def store_alerts(self, request, *args, **kwargs):
		result = {'data': {'error': "You have to login First"}, 'status': 403}
		if request.user.is_authenticated():
			result = {'data': {'error': 'No alerts given'}, 'status': 422}
			try:
				alerts = json.loads(request.body.decode("utf-8"));
				if alerts.get('alerts') and isinstance(alerts['alerts'], list):
					alerts = alerts['alerts']
					for alert in alerts:
						if (alert.get('hostName') and alert.get('alertType') and
							alert['alertType'] in ('ALERT_FILE', 'ALERT_RANSOMWARE') and alert.get('alertMessage') and
							alert.get('timeStamp') and validate_date(alert['timeStamp']) and alert.get('fileName')):
							pass
						else:
							raise ValueError('Invalid Json Format')
				else:
					raise ValueError('No alerts given')

				user = request.user
				for alert in alerts:
					try:
						host = Host.objects.get(
							name=url_decode(alert['hostName']),
							uuid=url_decode(alert['host_uuid']) if alert.get('host_uuid') else None,
							hardware_sn=url_decode(alert['hardware_sn']) if alert.get('hardware_sn') else None,
						)
						host.last_seen = datetime.datetime.now()
						host.save()
					except Host.DoesNotExist:
						host = Host.objects.create(
							name=url_decode(alert['hostName']),
							uuid=url_decode(alert['host_uuid']) if alert.get('host_uuid') else None,
							hardware_sn=url_decode(alert['hardware_sn']) if alert.get('hardware_sn') else None,
							last_seen=datetime.datetime.now()
						)

					for interface in alert.get('host_interfaces', []):
						_mac = interface.get('mac', None)
						if _mac:
							_name = interface.get('name')
							_address = interface.get('address', {})
							_ipv4 = _address.get('ipv4')
							_ipv6 = _address.get('ipv6')
							try:
								_interface = Interface.objects.get(host=host, mac=url_decode(_mac))
								_interface.name = url_decode(_name)if _name else _interface.name
								_interface.mac = url_decode(_mac)
								#_interface.address = url_decode(_address) if _address else _interface.address
								_interface.ipv4 = url_decode(_ipv4) if _ipv4 else _interface.ipv4
								_interface.ipv6 = url_decode(_ipv6) if _ipv6 else _interface.ipv6

								_interface.save()

							except Interface.DoesNotExist:
								Interface.objects.create(
									host=host,
									mac=url_decode(_mac),
									name=url_decode(_name),
									ipv4=url_decode(_ipv4),
									ipv6=url_decode(_ipv6)
								)

					alert = Alert.objects.create(
						host=host,
						fileName=url_decode(alert['fileName']),
						alertMessage=url_decode(alert['alertMessage']),
						alertType=url_decode(alert['alertType']),
						timeStamp=validate_date(alert['timeStamp']),
						created_by=user,
						process_name=url_decode(alert['process_name']) if 'process_name' in alert else None,
						host_ipaddr=url_decode(alert['host_ipaddr']) if 'host_ipaddr' in alert else None,
					)

					# Start GRR async task
					process_alert.delay(alert.alert_id)

				result = {'data': {'message': "alerts successfully recorded"}, 'status': 200}
			except ValueError as e:
				result = {'data': {'error': str(e)}, 'status': 422}
		return Response(data=result['data'], status=result['status'])

	def store_logs(self, request, *args, **kwargs):
		result = {'data': {'error': "You have to login First"}, 'status': 403}
		if request.user.is_authenticated():
			result = {'data': {'error': 'No logs given'}, 'status': 422}
			try:
				logs = json.loads(request.body.decode("utf-8"))
				if logs.get('logs') and isinstance(logs['logs'], list):
					logs = logs['logs']

					import os
					script_dir = os.path.dirname(__file__)
					rel_path = "logs/alert_cmd.json"
					file_path = os.path.join(script_dir, rel_path)
					for log in logs:
						json_data = json.dumps(log) + ",\n"
						with open(file_path, "ab") as f:
							f.write(bytes(json_data, 'utf-8'))
				else:
					raise ValueError('No logs given')
				result = {'data': {'message': "logs successfully recorded"}, 'status': 200}
			except ValueError as e:
				result = {'data': {'error': str(e)}, 'status': 422}
		return Response(data=result['data'], status=result['status'])

	def view_alerts(self, request, *args, **kwargs):
		result = {'data': {'error': "You have to login First"}, 'status': 403}
		if request.user.is_authenticated():
			if request.user.metadata.role_id < 3:
				result = {'data': {'error': 'No alerts Found'}, 'status': 204}
				try:
					page_number = request.GET.get('page_number')
					page_size = request.GET.get('page_size')
					search = request.GET.get('search')
					if not page_number:
						page_number = 1
					if not page_size:
						page_size = 10
					if not search:
						search = ""
					from .models import Alert
					from django.db.models import Q
					from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
					alerts = Alert.objects.filter(Q(host__name__icontains=search) | Q(fileName__icontains=search) | Q(
						alertMessage__icontains=search) | Q(process_name__icontains=search) | Q(
						host__uuid__icontains=search) | Q(host_ipaddr__icontains=search)).order_by('-timeStamp')
					length = len(alerts)
					if length:
						value = []
						for alert in alerts:
							user = alert.created_by
							user = {
								'first_name': user.first_name,
								'last_name': user.last_name,
								'email': user.email
							}
							tempValue = {
								'alert_id': alert.alert_id,
								'hostName': url_decode(alert.host.name),
								'fileName': url_decode(alert.fileName),
								'alertMessage': url_decode(alert.alertMessage),
								'timeStamp': alert.timeStamp.strftime("%d %b, %Y %I:%M %P"),
								'created_by': user,
								'created_at': alert.created_at.strftime("%d %b, %Y %I:%M %P"),
								'alertEval': alert.alertEval,
								'process_name': alert.process_name,
								'host_id': alert.host.id,
								'host_uuid': alert.host.uuid,
								'host_ipaddr': alert.host_ipaddr,
								'host_perform_lr': alert.host.perform_lr

							}
							value.append(tempValue)
						paginator = Paginator(value, page_size)
						try:
							value = paginator.page(page_number)
							data = {
								'alerts': value.object_list,
							}
							result = {'data': data, 'status': 200}
						except PageNotAnInteger:
							value = paginator.page(1)
							data = {
								'alerts': value.object_list,
							}
							result = {'data': data, 'status': 200}
						except EmptyPage:
							pass
				except Exception as e:
					result = {'data': {'error': str(e)}, 'status': 422}
			else:
				result = {'data': "Not Allowed to Service User", 'status': 401}
		return Response(data=result['data'], status=result['status'])

	def update_alert_eval(self, request, alert_id=None, EVAL=None):
		result = {'data': {'error': "You have to login First"}, 'status': 403}
		if request.user.is_authenticated():
			if request.user.metadata.role_id < 3:
				from .models import Alert
				alert = Alert.objects.filter(alert_id=alert_id).first()
				if alert and EVAL:
					alert.alertEval = int(EVAL)
					alert.save()
					result = {'data': "success", 'status': 200}
				else:
					result = {'data': "Alert not found", 'status': 404}
			else:
				result = {'data': "Not Allowed to Service User", 'status': 401}
		return Response(data=result['data'], status=result['status'])

	def view_host(self, request, host_id=None):
		result = {'data': {'error': "You have to login First"}, 'status': 403}
		if request.user.is_authenticated():
			if request.user.metadata.role_id < 3:

				host = Host.objects.filter(id=host_id).first()
				if host:
					interfaces = []
					for i in host.interfaces.all():
						interfaces.append({
							'id': i.id,
							'name': i.name,
							'mac': i.mac,
							'ipv4': i.ipv4,
							'ipv6': i.ipv6
						})

					result = {'data': {
						'id': host.id,
						'uuid': host.uuid,
						'name': host.name,
						'hardware_sn': host.hardware_sn,
						'grr_um': host.grr_um,
						'last_seen': host.last_seen,
						'perform_lr': host.perform_lr,
						'interfaces': interfaces
					}, 'status': 200}
				else:
					result = {'data': "Host not found", 'status': 404}
			else:
				result = {'data': "Not Allowed to Service User", 'status': 401}
		return Response(data=result['data'], status=result['status'])

	def update_host_lr(self, request, host_id=None):
		result = {'data': {'error': "You have to login First"}, 'status': 403}
		if request.user.is_authenticated():
			if request.user.metadata.role_id < 3:
				host = Host.objects.filter(id=host_id).first()

				if host:
					lr_state = request.POST.get('lr_state')
					if lr_state and lr_state == 'true' or lr_state == 'false':
						host_lrs = LiveResponse.objects.filter(host=host, complete=False)


						if lr_state == 'true':
							if host.perform_lr or host_lrs:
								result = {'data': {'error': 'Live response already in progress'}, 'status': 403}
							else:
								host.perform_lr = True
								perform_lr.delay(host_id)
								result = {'data': "success", 'status': 200}

						if lr_state == 'false' and host.perform_lr:
							for lr in host_lrs:
								cancel_lr.delay(lr.id)
							host.perform_lr = False
							host.save()
							result = {'data': "success", 'status': 200}
					else:
						result = {'data': {'error': "Live response state not found"}, 'status': 403}
				else:
					result = {'data': "Host not found", 'status': 404}
			else:
				result = {'data': "Not Allowed to Service User", 'status': 401}
		return Response(data=result['data'], status=result['status'])

	def view_lr(self, request, lr_id=None):
		result = {'data': {'error': "You have to login First"}, 'status': 403}
		if request.user.is_authenticated():
			if request.user.metadata.role_id < 3:
				lr = LiveResponse.objects.filter(id=lr_id).first()
				client_id = lr.host.grr_um
				flows = []
				for flow in lr.flows.all():
					f = {
						'type': LiveResponseFlow.FLOW_TYPES[flow.type][1],
						'flow_id': flow.flow_id,
						'client_id': client_id,
						'state': LiveResponseFlow.STATE_TYPES[flow.state][1],
						'state_messages': flow.state_messages,
					}
					flows.append(f)
				data = {'flows': flows}
				result = {'data': data, 'status': 200}
			else:
				result = {'data': "Not Allowed to Service User", 'status': 401}
		return Response(data=result['data'], status=result['status'])

	def get_alert_file_status(self, request, alert_id):
		result = {'data': {'error': "You have to login First"}, 'status': 403}
		if request.user.is_authenticated():
			if request.user.metadata.role_id < 3:
				alert = Alert.objects.filter(alert_id=alert_id).first()
				if alert:
					operation_id = flow_to_operation(alert.host.grr_um, alert.grr_file_flow_id)
					data = get_file_status(operation_id)
					result = {'data': data, 'status': 200}
				else:
					result = {'data': {'error': 'Alert object not found'}, 'status': 403}
			else:
				result = {'data': "Not Allowed to Service User", 'status': 401}
		return Response(data=result['data'], status=result['status'])

	def get_flow_result(self, request, client_id, flow_id):
		result = {'data': {'error': "You have to login First"}, 'status': 403}
		if request.user.is_authenticated():
			if request.user.metadata.role_id < 3:
				data = get_flow_result(client_id, flow_id)
				result = {'data': data, 'status': 200}
			else:
				result = {'data': "Not Allowed to Service User", 'status': 401}
		return Response(data=result['data'], status=result['status'])

	def get_host_lrs(self, request, host_id=None):
		result = {'data': {'error': "You have to login First"}, 'status': 403}
		if request.user.is_authenticated():
			if request.user.metadata.role_id < 3:
				host = Host.objects.filter(id=host_id).first()

				if host:
					data = []
					for lr in host.lrs.all():
						data.append({
							'lr_id': lr.id,
							'start_date': lr.start_date.strftime('%b. %d, %Y, %I:%M %p'),
							'complete': lr.complete
						})

					result = {'data': data, 'status': 200}
				else:
					result = {'data': "Host not found", 'status': 404}
			else:
				result = {'data': "Not Allowed to Service User", 'status': 401}
		return Response(data=result['data'], status=result['status'])

	def cancel_lr(self, request, lr_id=None):
		result = {'data': {'error': "You have to login First"}, 'status': 403}
		if request.user.is_authenticated():
			if request.user.metadata.role_id < 3:
				lr = LiveResponse.objects.filter(id=lr_id).first()
				if lr:
					cancel_lr.delay(lr.id)
					host = lr.host
					host.perform_lr = False
					host.save()
					result = {'data': "success", 'status': 200}
				else:
					result = {'data': "Live Response not found", 'status': 404}
			else:
				result = {'data': "Not Allowed to Service User", 'status': 401}
		return Response(data=result['data'], status=result['status'])

def validate_date(date_text):
	try:
		return datetime.datetime.strptime(date_text, '%H:%M, %d/%m/%Y').strftime("%Y-%m-%d %H:%M")
	except ValueError as e:
		raise ValueError("Incorrect data format, should be hh:mm, dd/mm/yyyy")
	return False


