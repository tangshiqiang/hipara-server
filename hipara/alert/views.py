from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from .models import Alert, Host
# Create your views here.

@login_required()
def alert_instance(request, alert_id):
	alert = Alert.objects.filter(alert_id = alert_id).first()
	title = "Alert - "

	if alert:
		title = "Alert - %s - %s" % (alert.host.name, alert.fileName)
	return render(request, 'alert_instance.html', {
		'alert': alert,
		'page': {'title': title}
	})