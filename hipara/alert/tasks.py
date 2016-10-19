import time
from datetime import timedelta, datetime
from celery.decorators import task, periodic_task
from celery.utils.log import get_task_logger
import grr_utils as gu
from .models import Alert, Host, LiveResponse, LiveResponseFlow

logger = get_task_logger(__name__)

@task(name='process_alert')
def process_alert(alert_id):
	"""
	A task to utilize GRR on the host to download the file from the alert
	:param alert_id: Integer - Value of the ID of the alert object
	:return: Dictionary - Values of client, flow, and operation ID or None
	"""
	# Get alert object
	alert = Alert.objects.filter(id=alert_id).first()

	# exit if alert isn't found
	if alert:
		logger.error('Unable to find alert from id %s' % alert_id)
		return None

	# Check if host has GRR UM ID
	client_id = None
	if alert.host.grr_um:
		client_id = alert.host.grr_um
	else:
		# Attempt to get a client id from GRR
		host = alert.host
		client_id = set_client_id(host)

	if client_id:
		# Issue Get file command
		operation_id = gu.get_file(client_id, alert.fileName)
		flow_id = gu.operation_to_flow(operation_id)

		# store result
		alert.grr_file_flow_id = flow_id
		alert.save()

		# store celery task result
		return {'client_id': client_id, 'flow_id': flow_id, 'operation_id': operation_id}

	return None


@task(name='set_client_id')
def set_client_id(host):
	"""
	Task to get client id from GRR for a supplied host
	:param host: Model Object -
	:return: String - The GRR Client ID. Ex: C.1000000000000000
	"""
	# Attempt to get a client id from GRR
	run = True
	run_count = 0
	client_id = None

	while (run and run_count < 5):
		gum = gu.get_client_urn(host)
		if gum:
			host.grr_um = gum
			host.save()
			run = False
			client_id = gum
		else:
			run_count += 1
			time.sleep(5)
	return client_id


@task(name='perform_lr')
def perform_lr(host_id):
	"""
	Task to start a Live Response on a specified host
	:param host_id: Integer - Host object id
	:return: JSON - Dictionaries containing flow IDs and LR object ID
	"""
	# Locate host
	host = Host.objects.filter(id=host_id).first()

	if host:
		# Create LR Object
		lr = LiveResponseFlow.objects.create(host=host)

		# List of flow IDs
		flows = []

		client_id = host.grr_um

		# get host os version
		os = gu.get_host_os(client_id)

		# update fs listing
		fs_flow_id = gu.update_fs_listing(client_id)
		if fs_flow_id:
			lr_fs_flow = LiveResponseFlow.objects.create(
				lr=lr, type=LiveResponseFlow.VFSRefresh, flow_id=fs_flow_id
			)
			flows.append({'lr_flow_id': lr_fs_flow, 'flow_id': fs_flow_id, 'type': 'VFSRefresh', 'complete': False})

		# Get memory
		mem_flow_id = gu.get_memory(client_id)
		if mem_flow_id:
			mem_lr_flow = LiveResponseFlow.objects.create(
				lr=lr, type=LiveResponseFlow.MemoryCollector, flow_id=mem_flow_id
			)
			flows.append({'lr_flow_id': mem_lr_flow, 'flow_id': mem_flow_id, 'type': 'MemoryCollector', 'complete': False})

		# get running processes
		process_flow_id = gu.get_processes(client_id)
		if process_flow_id:
			process_lr_flow = LiveResponseFlow.objects.create(
				lr=lr, type=LiveResponseFlow.ListProcesses, flow_id=process_flow_id
			)
			flows.append({'lr_flow_id': process_lr_flow, 'flow_id': process_flow_id, 'type': 'ListProcesses', 'complete': False})

		# get netstat
		netstat_flow_id = gu.get_netstat(client_id)
		if netstat_flow_id:
			netstat_lr_flow = LiveResponseFlow.objects.create(
				lr=lr, type=LiveResponseFlow.Netstat, flow_id=netstat_flow_id
			)
			flows.append({'lr_flow_id': netstat_lr_flow, 'flow_id': netstat_flow_id, 'type': 'Netstat', 'complete': False})

		# get logs
		logs_flow_id = None
		scheduled_task_flow_id = None
		registry_flow_id = None

		if os == "Windows":
			logs_flow_id = gu.get_windows_logs(client_id)
			scheduled_task_flow_id = gu.get_windows_scheduled_tasks(client_id)
			registry_flow_id = gu.get_windows_registry(client_id)
		elif os == "Linux":
			logs_flow_id = gu.get_linux_logs(client_id)
		elif os == "Darwin":
			logs_flow_id = gu.get_osx_logs(client_id)

		if logs_flow_id:
			logs_lr_flow = LiveResponseFlow.objects.create(
				lr=lr, type=LiveResponseFlow.Logs, flow_id=logs_flow_id
			)
			flows.append({'lr_flow_id': logs_lr_flow, 'flow_id': logs_flow_id, 'type': 'Logs', 'complete': False})

		# get scheduled tasks
		if scheduled_task_flow_id:
			scheduled_task_lr_flow = LiveResponseFlow.objects.create(
				lr=lr, type=LiveResponseFlow.Cron, flow_id=scheduled_task_flow_id
			)
			flows.append({'lr_flow_id': scheduled_task_lr_flow, 'flow_id': scheduled_task_flow_id, 'type': 'Cron', 'complete': False})

		# get registry
		if registry_flow_id:
			registry_lr_flow = LiveResponseFlow.objects.create(
				lr=lr, type=LiveResponseFlow.Registry, flow_id=registry_flow_id
			)
			flows.append({'lr_flow_id': registry_lr_flow, 'flow_id':registry_flow_id, 'type': 'Registry', 'complete': False})

		return {'lr_id': lr.id, 'flows': flows}


@task(name='cancel_lr')
def cancel_lr(lr_id):
	# Locate LR object
	lr = LiveResponse.objects.filter(id=lr_id).first()

	if lr:
		client_id = lr.host.grr_um

		for lrf in lr.flows.all():
			if lrf.state != LiveResponseFlow.Running:
				if gu.cancel_flow(client_id, lrf.flow_id):
					lrf.state = LiveResponseFlow.Error
					lrf.save()
				else:
					logger.error("host: %s - Unable to cancel flow %s" % lr.host.name, lrf.flow_id)

		lr.complete = True
		lr.save()


@periodic_task(run_every=timedelta(seconds=30), name="check_lrs")
def check_lrs():
	# Get LR objects where complete is false
	for lr in LiveResponse.objects.filter(complete=False):
		client_id = lr.host.grr_um
		flows = lr.flows.filter(state=LiveResponseFlow.Running)
		completed = 0
		for lrf in lr.flows.filter(state=LiveResponseFlow.Running):
			flow_status = gu.get_flow_status(client_id, lrf.flow_id)
			if flow_status:
				if flow_status.get('complete'):
					lrf.state = LiveResponseFlow.Complete
					lrf.save()
					completed += 1
				else:
					if flow_status.get('error'):
						lrf.state = LiveResponseFlow.Error
						lrf.state_messages = flow_status.get('state_messages')
						lrf.save()
						completed += 1

		if completed == len(flows):
			lr.complete = True
			lr.save()
