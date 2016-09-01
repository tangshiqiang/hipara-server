from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
from django.http import HttpResponse
from . import views
import os, json

class CsrfExemptSessionAuthentication(SessionAuthentication):

    def enforce_csrf(self, request):
        return

class SettingsViewSet(viewsets.ViewSet):
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)

    def config_fetch(self, request, *args, **kwargs):
        result = {'data': {'error': "You have to login First"}, 'status': 403}
        if request.user.is_authenticated():
            md5sum = request.GET.get('md5sum')
            configJsonFile = views.getConfigFile();
            if configJsonFile:
                if md5sum != configJsonFile['md5sum'] :
                    currentDir = os.path.dirname(__file__)
                    configFileRelativePath = "storage/config/"+configJsonFile['fileName']
                    configFilePath = os.path.join(currentDir, configFileRelativePath)
                    configFileData = open(configFilePath, "rb").read()
                    response = HttpResponse(configFileData, content_type='text/plain')
                    response['Content-Disposition'] = 'attachment; filename="'+configJsonFile['fileName']+'"'
                    return response
                else:
                    result = {'data': {'message': "There is no new config file"}, 'status': 201}
            else:
                result = {'data': {'error': "There is no config file. Request admin to upload config file"}, 'status': 404}
        return Response(data=result['data'], status=result['status'])

    def routine_fetch(self, request, *args, **kwargs):
        result = {'data': {'error': "You have to login First"}, 'status': 403}
        if request.user.is_authenticated():
            currentDir = os.path.dirname(__file__)
            routineJsonFileRelativePath = "storage/routine/routineOptions.json"
            routineJsonFileFullPath = os.path.join(currentDir, routineJsonFileRelativePath)
            with open(routineJsonFileFullPath) as routineFile:
                data = json.load(routineFile)
            result = {'data':data, 'status':200}
        return Response(data=result['data'], status=result['status'])

    def msi_package_build(self, request, *args, **kwargs):
        result = {'data': {'error': "You have to login First"}, 'status': 403}
        if request.user.is_authenticated():
            msiPackageJsonFile = views.getMsiPackageFile();
            if msiPackageJsonFile:
                result = {'data': {'buildNumber': msiPackageJsonFile['buildNumber'] }, 'status': 200}
            else:
                result = {'data': {'error': "There is no MSI package. Request admin to upload MSI package"}, 'status': 404}
        return Response(data=result['data'], status=result['status'])

    def download_msi_package(self, request, build_number, *args, **kwargs):
        result = {'data': {'error': "You have to login First"}, 'status': 403}
        if request.user.is_authenticated():
            msiPackageJsonFile = views.getMsiPackageFile();
            if msiPackageJsonFile:
                if msiPackageJsonFile['buildNumber'] == int(build_number) :
                    currentDir = os.path.dirname(__file__)
                    msiPackageFileRelativePath = "storage/msi_package/"+msiPackageJsonFile['fileName']
                    msiPackageFilePath = os.path.join(currentDir, msiPackageFileRelativePath)
                    msiPackageFileData = open(msiPackageFilePath, "rb").read()
                    response = HttpResponse(msiPackageFileData)
                    response['Content-Disposition'] = 'attachment; filename="'+msiPackageJsonFile['fileName']+'"'
                    return response
            result = {'data': {'error': "There is no MSI package with this build"}, 'status': 404}
        return Response(data=result['data'], status=result['status'])