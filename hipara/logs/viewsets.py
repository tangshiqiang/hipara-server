from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
import json
import datetime

class CsrfExemptSessionAuthentication(SessionAuthentication):

    def enforce_csrf(self, request):
        return


class LogsViewSet(viewsets.ViewSet):
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)

    def store_logs(self, request, *args, **kwargs):
        result = {'data': {'error':"You have to login First"}, 'status': 403}
        if request.user.is_authenticated():
            result = {'data': {'error':'No logs given'}, 'status': 422}
            try:
                logs = json.loads(request.body.decode("utf-8"));
                if 'logs' in logs and isinstance(logs['logs'], list) and logs['logs']:
                    logs = logs['logs']
                    for log in logs:
                        if('hostname' in log and log['hostname'] and 'fileName' in log and log['fileName'] and 'alertMessage' in log and log['alertMessage'] and 'timeStamp' in log and log['timeStamp'] and validate_date(log['timeStamp'])):
                            pass
                        else:
                            raise ValueError('Invalid Json Format')
                else:
                    raise ValueError('No logs given')
                from .models import Alert
                user = request.user
                for log in logs:
                    Alert.objects.create(
                        hostName=log['hostname'],
                        fileName=log['fileName'],
                        alertMessage=log['alertMessage'],
                        timeStamp=validate_date(log['timeStamp']),
                        created_by=user
                    )
                result = {'data': {'message':"logs successfully recorded"}, 'status': 200}
            except ValueError as e:
                result = {'data': {'error':str(e)}, 'status': 422}
        return Response(data=result['data'], status=result['status'])

    def view_logs(self, request, *args, **kwargs):
        result = {'data': {'error':"You have to login First"}, 'status': 403}
        if request.user.is_authenticated():
            result = {'data': {'error':'No logs Found'}, 'status': 204}
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
                logs = Alert.objects.filter(Q(hostName__icontains=search) | Q(fileName__icontains=search) | Q(alertMessage__icontains=search))
                length = len(logs)
                if length :
                    value = []
                    for log in logs:
                        user = log.created_by
                        user = {
                            'first_name':user.first_name,
                            'last_name':user.last_name,
                            'email':user.email
                        }
                        tempValue = {
                            'alert_id':log.alert_id,
                            'hostName':log.hostName,
                            'fileName':log.fileName,
                            'alertMessage':log.alertMessage,
                            'timeStamp':log.timeStamp.strftime("%H:%M, %d/%m/%y"),
                            'created_by':user,
                            'created_at':log.created_at.strftime("%d %b, %Y %I:%M %P"),

                        }
                        value.append(tempValue)
                    paginator = Paginator(value, page_size)
                    try:
                        value = paginator.page(page_number)
                        data ={
                            'logs':value.object_list,
                        }
                        result = {'data': data, 'status': 200}
                    except PageNotAnInteger:
                        value = paginator.page(1)
                        data ={
                            'logs':value.object_list,
                        }
                        result = {'data': data, 'status': 200}
                    except EmptyPage:
                        pass
            except Exception as e:
                result = {'data': {'error':str(e)}, 'status': 422}
        return Response(data=result['data'], status=result['status'])


def validate_date(date_text):
    try:
        return datetime.datetime.strptime(date_text, '%H:%M, %d/%m/%y').strftime("%Y-%m-%d %H:%M")
    except ValueError as e:
        raise ValueError("Incorrect data format, should be hh:mm, dd/mm/yy")
    return False
