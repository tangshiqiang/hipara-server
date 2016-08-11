from django.shortcuts import render
from django.shortcuts import redirect
from registration.utils import get_page
import json, datetime, os, hashlib
from django.core.files.base import ContentFile
from .forms import UploadConfigForm, UpdateRoutineForm

def config_view(request):
    if request.user.is_authenticated():
        if request.user.metadata.role_id == 1:
        	if request.method == 'POST':
        		form = UploadConfigForm(request.POST, request.FILES)
        		if form.is_valid():
        			storeConfigFile(request.FILES['configFile'])
        			form.add_error(None, 'Config file uploaded Successfully')
        	else:
        		form = UploadConfigForm(initial={})
        	configFile = getConfigFile()
        	return render(request, 'config.html', {'form': form, 'configFile' :configFile, 'page': get_page('config')})
    return redirect('index')

def routine_view(request):
    if request.user.is_authenticated():
        if request.user.metadata.role_id == 1:
        	rel_path = "storage/routine/routineOptions.json"
        	file_path = getFullFilePath(rel_path)

        	if request.method == 'POST':
        		form = UpdateRoutineForm(request.POST)
        		if form.is_valid():
        			data = {
        				"fullDiskScan": form.cleaned_data.get('fullDiskScan'), 
        				"memoryScan": form.cleaned_data.get('memoryScan')
        			}
        			json_data = json.dumps(data)
        			with open(file_path, "wb") as f:
        				f.write(bytes(json_data, 'utf-8'))
        			form.add_error(None, 'Routine Options Updated Successfully')
        	else:
        		
        		with open(file_path) as routineFile:
        			data = json.load(routineFile)
        		form = UpdateRoutineForm(initial=data)
        	return render(request, 'routine.html', {'form': form, 'page': get_page('routine')})
    return redirect('index')

def storeConfigFile(file):
	configFileRelativePath = "storage/config/"+file.name
	configFilePath = getFullFilePath(configFileRelativePath)
	md5sum = hashlib.md5()

	fout = open(configFilePath, 'wb+')
	file_content = ContentFile( file.read() )
	for chunk in file_content.chunks():
		fout.write(chunk)
		md5sum.update(chunk)
	fout.close()

	configJsonFileRelativePath = "storage/config/configFile.json"
	configJsonFilePath = getFullFilePath(configJsonFileRelativePath)

	configFile = {
		"fileName": file.name, 
		"md5sum": md5sum.hexdigest(),
		"updatedAt" : datetime.datetime.now().strftime("%d %b, %Y %I:%M %P")
	}

	deleteConfigFile()

	json_data = json.dumps(configFile)
	with open(configJsonFilePath, "wb") as f:
		f.write(bytes(json_data, 'utf-8'))

def getConfigFile():
	rel_path = "storage/config/configFile.json"
	file_path = getFullFilePath(rel_path)
	if os.path.isfile(file_path) :
		with open(file_path) as config_file:
			configFile = json.load(config_file)
	else:
		configFile = None
	return configFile

def getFullFilePath(fileRelativePath):
	currentDir = os.path.dirname(__file__)
	return os.path.join(currentDir, fileRelativePath)

def deleteConfigFile():
	configJsonFile = getConfigFile()
	if configJsonFile :
		configFileRelativePath = "storage/config/"+configJsonFile['fileName']
		configFilePath = getFullFilePath(configFileRelativePath)
		os.remove(configFilePath) 
