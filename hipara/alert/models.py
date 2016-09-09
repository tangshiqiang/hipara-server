from django.db import models
from django.contrib.auth.models import User
from datetime import datetime

class Host(models.Model):
	uuid = models.CharField(max_length=50, db_index=True, blank=True, null=True)
	name = models.CharField(max_length=128, db_index=True)
	last_seen = models.DateTimeField(default=datetime.now)

	class Meta:
		unique_together = ['uuid', 'name']

	def __str__(self):
		return self.name

class Alert(models.Model):
	ALERT_FILE	=	'ALERT_FILE' 
	ALERT_CMD	=	'ALERT_CMD'
	ALERT_TYPE	=	(
		(ALERT_FILE, 'ALERT_FILE'),
		(ALERT_CMD, 'ALERT_CMD')
	)
	ALERT_EVAL = (
		(0, None),
		(1, "TRUE_POSITIVE"),
		(2, "FALSE_POSITIVE")
	)
	
	alert_id = models.AutoField(primary_key=True)
	host = models.ForeignKey(Host, blank=True, null=True, related_name="alerts")
	fileName = models.CharField(max_length=200)
	alertMessage = models.CharField(max_length=250)
	alertType = models.CharField(max_length=250, choices=ALERT_TYPE, default=ALERT_FILE)
	timeStamp = models.DateTimeField()
	created_by = models.ForeignKey(User, related_name='created_alert', blank=True, null=True)
	created_at = models.DateTimeField(auto_now_add=True)
	alertEval = models.IntegerField(choices=ALERT_EVAL, default=0)
	process_name = models.CharField(max_length=250, blank=True, null=True, default=None)
	host_ipaddr = models.CharField(max_length=250, blank=True, null=True, default=None)

	def __str__(self):
		return self.host.name
