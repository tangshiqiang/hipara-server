from django.shortcuts import render
from django.shortcuts import redirect
from registration.utils import get_page
import json, datetime, os, hashlib
from django.core.files.base import ContentFile
from .forms import UploadConfigForm, UpdateRoutineForm, UploadMsiPackageForm

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

def msi_package_view(request):
	if request.user.is_authenticated():
		if request.user.metadata.role_id == 1:
			if request.method == 'POST':
				form = UploadMsiPackageForm(request.POST, request.FILES)
				if form.is_valid():
					storeMsiPackageFile(form.cleaned_data.get("msiPackageFile"), form.cleaned_data.get('buildNumber'))
					form.add_error(None, 'MSI package uploaded Successfully')
			else:
				form = UploadMsiPackageForm(initial={"buildNumber":""})
			msiPackageFile = getMsiPackageFile()
			return render(request, 'msiPackage.html', {'form': form, 'msiPackageFile' :msiPackageFile, 'page': get_page('msiPackage')})
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

def storeMsiPackageFile(file, buildNumber):
	msiPackageFileRelativePath = "storage/msi_package/"+file['fileName']
	msiPackageFilePath = getFullFilePath(msiPackageFileRelativePath)

	deleteMsiPackageFile()


	fout = open(msiPackageFilePath, 'wb+')
	file_content = ContentFile( file['fileContent'] )
	for chunk in file_content.chunks():
		fout.write(chunk)
	fout.close()

	msiPackageJsonFileRelativePath = "storage/msi_package/msiPackageFile.json"
	msiPackageJsonFilePath = getFullFilePath(msiPackageJsonFileRelativePath)

	msiPackageFile = {
		"fileName": file['fileName'], 
		"buildNumber" : buildNumber
	}

	json_data = json.dumps(msiPackageFile)
	with open(msiPackageJsonFilePath, "wb") as f:
		f.write(bytes(json_data, 'utf-8'))

def getMsiPackageFile():
	rel_path = "storage/msi_package/msiPackageFile.json"
	file_path = getFullFilePath(rel_path)
	if os.path.isfile(file_path) :
		with open(file_path) as msi_package_file:
			msiPackageFile = json.load(msi_package_file)
	else:
		msiPackageFile = None
	return msiPackageFile


def deleteMsiPackageFile():
	msiPackageFile = getMsiPackageFile()
	if msiPackageFile :
		msiPackageFileRelativePath = "storage/msi_package/"+msiPackageFile['fileName']
		msiPackageFilePath = getFullFilePath(msiPackageFileRelativePath)
		os.remove(msiPackageFilePath) 
