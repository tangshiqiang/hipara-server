from django.shortcuts import render
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from .models import Alert, Host
from .grr_utils import download_file, flow_to_operation, get_file_status
from wsgiref.util import FileWrapper

# Create your views here.

@login_required()
def alert_instance(request, alert_id):
	alert = Alert.objects.filter(alert_id = alert_id).first()
	title = "Alert - "
	file_status = None

	if alert:
		title = "Alert - %s - %s" % (alert.host.name, alert.fileName)
		if alert.grr_file_flow_id:
			file_status = get_file_status(flow_to_operation(alert.host.grr_um, alert.grr_file_flow_id))
	return render(request, 'alert_instance.html', {
		'alert': alert,
		'page': {'title': title},
		'file_status': file_status
	})

@login_required()
def download_alert_file(request, client_id, flow_id):
	if client_id and flow_id:
		_file = download_file(client_id, flow_id)
		mimetype = "application/octet-stream"
		response = HttpResponse(_file.content, content_type=mimetype)
		response['Content-Disposition'] = 'attachment; filename="hiparafile.zip"'
		return response
	else:
		return HttpResponse('error')