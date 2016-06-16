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

def validate_date(date_text):
    try:
        return datetime.datetime.strptime(date_text, '%H:%M, %d/%m/%y').strftime("%Y-%m-%d %H:%M")
    except ValueError as e:
        raise ValueError("Incorrect data format, should be hh:mm, dd/mm/yy")
    return False
