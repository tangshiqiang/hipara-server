from django.db import models
from django.contrib.auth.models import User
from datetime import datetime

class Host(models.Model):
	uuid = models.CharField(max_length=50, db_index=True, blank=True, null=True)
	name = models.CharField(max_length=128, db_index=True)
	last_seen = models.DateTimeField(default=datetime.now)
	hardware_sn = models.CharField(max_length=256, db_index=True, blank=True, null=True)
	grr_um = models.CharField(max_length=256, db_index=True, blank=True, null=True)
	perform_lr = models.BooleanField(default=False)

	class Meta:
		unique_together = ['uuid', 'name', 'hardware_sn']

	def __str__(self):
		return self.name

class Interface(models.Model):
	host = models.ForeignKey(Host, related_name="interfaces")
	name = models.CharField(max_length=256)
	mac = models.CharField(max_length=17)
	ipv4 = models.CharField(max_length=15, blank=True, null=True)
	ipv6 = models.CharField(max_length=45, blank=True, null=True)

	class Meta:
		unique_together = ['host', 'mac']

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
	grr_file_flow_id = models.CharField(max_length=100, blank=True, null=True)

	def __str__(self):
		return self.host.name

class LiveResponse(models.Model):
	host = models.ForeignKey(Host, related_name="lrs")
	complete = models.BooleanField(default=False)
	start_date = models.DateTimeField(default=datetime.now)

class LiveResponseFlow(models.Model):

	# Flow Types
	VFSRefresh = 0
	MemoryCollector = 1
	ListProcesses = 2
	Netstat = 3
	Logs = 4
	Cron = 5
	Registry = 6

	FLOW_TYPES = (
		(VFSRefresh, "VFSRefresh"),
		(MemoryCollector, "MemoryCollector"),
		(ListProcesses, "ListProcesses"),
		(Netstat, "Netstat"),
		(Logs, "Logs"),
		(Cron, "Cron"),
		(Registry, "Registry"),
	)

	# State Types
	Running = 0
	Complete = 1
	Error = 2
	Canceled = 3
	STATE_TYPES = (
		(Running, "Running"),
		(Complete, "Complete"),
		(Error, "Error"),
		(Canceled, "Canceled")
	)

	lr = models.ForeignKey(LiveResponse, related_name="flows")
	type = models.IntegerField(choices=FLOW_TYPES)
	flow_id = models.CharField(max_length=32)
	state = models.IntegerField(choices=STATE_TYPES, default=Running)
	state_messages = models.CharField(max_length=1000, blank=True, null=True)
