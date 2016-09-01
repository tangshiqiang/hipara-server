from django.db import models
from django.contrib.auth.models import User

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
	hostName = models.CharField(max_length=128)
	fileName = models.CharField(max_length=200)
	alertMessage = models.CharField(max_length=250)
	alertType = models.CharField(max_length=250, choices=ALERT_TYPE, default=ALERT_FILE)
	timeStamp = models.DateTimeField()
	created_by = models.ForeignKey(User, related_name='created_alert', blank=True, null=True)
	created_at = models.DateTimeField(auto_now_add=True)
	alertEval = models.IntegerField(choices=ALERT_EVAL, default=0)

	def __str__(self):
		return self.hostName