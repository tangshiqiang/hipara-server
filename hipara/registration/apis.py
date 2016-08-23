
def getLoginApiDocument():
    return {
        'title': "Login",
        'url': '/api/v1/auth/login',
        'description': 'This is login endpoint. After successful login capture cookie (hipara) from response header to call authenticated api\'s afterword.',
        'method': 'POST',
        'header': """{ 
    Content-Type: application/json 
}""",
        'dataparams': """{
    "email":<alphanumeric>, 
    "password":<alphanumeric>
}""",
        'response':{
            'success': [
                {
                    'code': 200,
                    'content': """ "Login Successful" """
                },
                {
                    'code': 200,
                    'content': """ "Already Logged In" """
                }
            ],
            'error':[
                {
                    'code': 422,
                    'content': """ "Invalid Username and/or Password" """
                },
                {
                    'code': 403,
                    'content': """ "This account has been disabled contact to admin" """
                },
                {
                    'code': 422,
                    'content': """{
    "email": ["This field is required."],
    "password": ["This field is required."]
}"""
                },
                {
                    'code': 422,
                    'content': """{
    "password": ["This field is required."]
}"""
                }
            ]
        },
        'example': """
        import requests
        import json
        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'

        session = requests.Session()   # to manage cookies

        data = {"email":"email", "password":"password"}

        response = session.post(host + login_url, data=data)

        if(response.ok) :
            print("Login Success")
            print("Content : "+response.content.decode())
            print("Status Code : " + str(response.status_code))

        else :
            print("Login Failure")
            print("Content : "+ response.content.decode())
            print("Status Code : " + str(response.status_code))
    """
        }

def getLogoutApiDocument():
    return {
        'title': "Logout",
        'url': "/api/v1/auth/logout",
        'description': "This is logout endpoint. Need to send authenticated cookies with the request header.",
        'method': "GET",
        'header': """{ 
    Cookie: '<cookie_name>=CookieFromLoginResponse' 
}""",
        'response':{
            'success':[
                {
                    'code': 200,
                    'content': """ "Logout successful" """
                }
            ],
            'error':[
                {    
                    'code': 403,
                    'content': """ "You have to login First" """
                }
            ]
        },
            'example': """
        import requests
        import json
        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'


        session = requests.Session()

        data = {"email":"email", "password":"password"}

        response = session.post(host + login_url, data=data)

        if(response.ok) :
            print("Success")
            print("Content : "+response.content.decode())
            print("Status Code : " + str(response.status_code))

            response = session.get(host + logout_url)
            if(response.ok) :
                print("Logout Success")
                print("Content : "+response.content.decode())
                print("Status Code : " + str(response.status_code))
            else :
                print("Logout Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))

        else :
            print("Login Failure")
            print("Content : "+ login_response.content.decode())
            print("Status Code : " + str(login_response.status_code))
    """
    }

def getUploadRuleApi():
	return {
		'title': "Upload signature rule file",
        'url': "/api/v1/import",
        'description': "This is upload signature (yar) file. File extetion should be .yar",
        'method': "POST",
        'header': """{ 
    Content-Type: multipart/form-data, 
    Cookie: '<cookie_name>=CookieFromLoginResponse' 
}""",
        'dataparams': """{
	"rule_file" :   <file or read stream>, 
	"category"  :   <numeric from (1 ,2)> (Hipara, PhishFry),
	"source"    :   <alphanumeric>
}""",
        'response':{
            'success':[
                {
                    'code': 200,
                    'content': """ "Successfully import rule file" """
                }
            ],
            'error':[
                {
                    'code': 422,
                    'content': """{
    "rule_file": [ "This field is required."],
    "category": ["This field is required."],
    "source": ["This field is required." ] 
}"""
				},
                {
                    'code': 422,
                    'content': """{
	"rule_file": [ "Name for rule is already been taken : Bioazih_RAT" ]
}"""
                },
                {
                    'code': 403,
                    'content': """ "You have to login First" """
                }
            ]
        },
        'example':"""
        import requests
        import json
        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'
        upload_url = '/api/v1/import'

        session = requests.Session()

        data = {"email":"email", "password":"password"}

        response = session.post(host + login_url, data=data)

        if(response.ok) :
            print("Success")
            print("Content : "+response.content.decode())
            print("Status Code : " + str(response.status_code))

            files = {'rule_file': open('apt_win_banrub_b.yar', 'rb')}
            data =  {"category" : 1,"source" : "Public exchange"}
            response = session.post(host + upload_url, files=files, data=data)
            if(response.ok) :
                print("Upload Success")
                print("Content : "+response.content.decode())
                print("Status Code : " + str(response.status_code))
            else :
                print("Upload Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))

            response = session.get(host + logout_url)
            if(response.ok) :
                print("Logout Success")
                print("Content : "+response.content.decode())
                print("Status Code : " + str(response.status_code))
            else :
                print("Logout Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))
        else :
            print("Login Failure")
            print("Content : "+ response.content.decode())
            print("Status Code : " + str(response.status_code))
    """
	}

def getDownloadRuleCategoryApi():
	return {
		'title': "Download yar signatures depending on category and status",
        'url': "/api/v1/export",
        'description': "This api downloads all yara signatures depending on category and status. Default category is \"Hipara\" and status is \"Deployed\". Values for category= 0 : All, * : any category id (like 1 for Hipara). Values for status=  -2 : All, -1 : Pending approval, 0 : Not Deployed, 1 : Deployed.",
        'method': "GET",
        'header': """{ 
    Cookie: '<cookie_name>=CookieFromLoginResponse' 
}""",
        'dataparams': """{ 
    "status":<number>, "category":<number> 
}""",
        'response': {
            'success':[
                {
                   	'code': 200,
                    'content': """ "File will be downloaded with desired category and status" """
                },
                {
                    'code': 204,
                   	'content': """ "Nothing To Download" """
                }
            ],
            'error':[
                {
                    'code': 422,
                    'content': """ "Invalid Input Given" """
                },
                {
                    'code': 403,
                    'content': """ "You have to login First" """
                }
            ]
        },
        'example':"""
        import requests
        import json
        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'
        download_url = '/api/v1/export'


        session = requests.Session()

        data = {"email":"email", "password":"password"}

        response = session.post(host + login_url, data=data)

        if(response.ok) :
            print("Success")
            print("Content : "+response.content.decode())
            print("Status Code : " + str(response.status_code))

            response = session.get(host + download_url)
            if(response.ok) :
                print("Download Success")
                path = "rules.yar"
                with open(path, 'wb') as f :
                    content = response.content
                    f.write(content)
                print("file : "+path)
                print("Status Code : " + str(response.status_code))
            else :
                print("Download Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))

            response = session.get(host + logout_url)
            if(response.ok) :
                print("Logout Success")
                print("Content : "+response.content.decode())
                print("Status Code : " + str(response.status_code))
            else :
                print("Logout Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))
        else :
            print("Login Failure")
            print("Content : "+ response.content.decode())
            print("Status Code : " + str(response.status_code))
    """
	}

def getStoreAplertsApi():
	return {
		'title': "Store Signature Detection alerts",
        'url': "/api/v1/alerts",
        'description': "This is stores alerts of signature detection on host machine. Alert json should have \"fileName\" key for alertType \"ALERT_FILE\" and \"command\" key for alertType \"ALERT_CMD\".",
        'method': "POST",
        'header': """{ 
    Cookie: '<cookie_name>=CookieFromLoginResponse' 
}""",
        'dataparams': """{
    "alerts" :   [
    	{
    		"hostName":<string>, 
    		"fileName/command":<string>, 
		    "alertMessage":<string>, 
		    "alertType" : <ALERT_FILE/ALERT_CMD>, 
		    "parentProcessId":<integer required if ALERT_CMD>timeStamp":<"hh:mm, dd/mm/yyyy" date> 
		}
	]
}""",
        'response':{
            'success':[
                {
                    'code': 200,
                    'content': """{ 
    "message": "alerts successfully recorded" 
}"""
				}],
            'error':[
                {
                    'code': 422,
                    'content': """{ 
    "error": "Some error message" 
}"""
				},
                {
                    'code': 403,
                    'content': """{ 
    "error": "You have to login First" 
}"""
				}
			]
		},
        'example': """
        import requests
        import json
        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'
        store_alerts_url = '/api/v1/alerts'


        session = requests.Session()

        data = {"email":"email", "password":"password"}

        response = session.post(host + login_url, data=data)

        if(response.ok) :
            print("Success")
            print("Content : "+response.content.decode())
            print("Status Code : " + str(response.status_code))

            data =  {
                "alerts":[
                        {
                            "hostName":"COMPUTER1",
                            "fileName":"c:\\\\ABC\\\\pqr.txt",
                            "alertMessage":"Trojan Found",
                            "alertType":"ALERT_FILE",
                            "timeStamp":"15:59, 31/12/1948"
                        },
                        {
                            "hostName":"COMPUTER1",
                            "command":"dpkg -i nginx.deb",
                            "alertMessage":"Trojan Found",
                            "parentProcessId":3306,
                            "alertType":"ALERT_CMD",
                            "timeStamp":"11:00, 01/01/2001"
                        },
                        {
                            "hostName":"COMPUTER1",
                            "command":"curl http://45.33.88.157/",
                            "alertMessage":"Trojan Found",
                            "parentProcessId":45455,
                            "alertType" :   "ALERT_CMD",
                            "timeStamp":"01:00, 01/01/2016"
                        }
                    ]
            }
            headers = {'Content-Type': 'application/json'}
            response = session.post(host + store_alerts_url, data=json.dumps(data),  headers=headers)
            if(response.ok) :
                print("Store alerts Success")
                print("Content : "+response.content.decode())
                print("Status Code : " + str(response.status_code))
            else :
                print("Store alerts Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))

            response = session.get(host + logout_url)
            if(response.ok) :
                print("Logout Success")
                print("Content : "+response.content.decode())
                print("Status Code : " + str(response.status_code))
            else :
                print("Logout Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))
        else :
            print("Login Failure")
            print("Content : "+ response.content.decode())
            print("Status Code : " + str(response.status_code))
    """

	}

def getListAlertsApi():
	return {
		'title': "Get list of Signature Detection alerts",
        'url': "/api/v1/alerts",
        'description': "This lists alerts of signature detected on host machine and stored on server",
        'method': "GET",
        'header': """{ 
    Content-Type: application/json, 
    Cookie: '<cookie_name>=CookieFromLoginResponse' 
}""",
        'dataparams': """{ 
    "page_number":<number>, 
    "page_size":<number>, 
    "search":<string on hostname, fileName, alertMessage> 
}""",
        'response':{
            'success':[
                {
                    'code': 200,
                    'content': """{ 
    "alerts": [ 
    	{ 
    		"alert_id": 15, 
    		"hostName": "COMPUTER1", 
    		"fileName": "FILE1", 
    		"alertMessage": "Trojan Found", 
    		"timeStamp": "18 Jun, 2016 07:06 am", 
    		"created_at": "18 Jun, 2016 07:06 am", 
    		"created_by": { 
    			"email": "user@hipara.org", 
    			"last_name": "Admin", 
    			"first_name": "Admin" 
    		} 
    	} 
    ] 
}"""
				},
                {
                    'code': 204,
                    'content': "There is no content"
                }
            ],
            'error':[
                {
                    'code': 422,
                    'content': """{ 
    "error": "Some error message" 
}"""
				},
                {
                   	'code': 403,
                    'content': """{ 
	"error": "You have to login First" 
}"""
				}
			],
		},
        'example': """
        import requests
        import json

        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'
        get_alerts_url = '/api/v1/alerts'


        session = requests.Session()

        data = {"email":"email", "password":"password"}

        response = session.post(host + login_url, data=data)

        if(response.ok) :
            print("Success")
            print("Content : "+response.content.decode())
            print("Status Code : " + str(response.status_code))
            data = {
                'page_number':1,
                'page_size' :10,
                'search'    : ''
            }
            response = session.get(host + get_alerts_url, params=data)
            if(response.status_code == 200) :
                print("Get alerts Success")
                print("Content of first alert: "+response.content.decode())
                print("Status Code : " + str(response.status_code))
            elif(response.status_code == 204):
                print("Get alerts Empty")
                print("There is no content to show")
                print("Status Code : " + str(response.status_code))
            else :
                print("Get alerts Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))

            response = session.get(host + logout_url)
            if(response.ok) :
                print("Logout Success")
                print("Content : "+response.content.decode())
                print("Status Code : " + str(response.status_code))
            else :
                print("Logout Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))
        else :
            print("Login Failure")
            print("Content : "+ response.content.decode())
            print("Status Code : " + str(response.status_code))
    """
	}

def getDownloadConfigFileApi():
	return {
		'title': "Download Config file",
        'url': "/api/v1/config/fetch/",
        'description': "Download the config file which is stored on the server. To get new config file client has to send md5 checksum of the available file if server has new config file the new will be downloaded otherwise nothing is downloaded",
        'method': "GET",
        'header': """{  
    Cookie: '<cookie_name>=CookieFromLoginResponse' 
}""",
        'dataparams': """{ 
    "md5sum":<md5 checksum of config file>  #if first time then it can be null
}""",
        'response':{
            'success':[
                {
                    'code': 200,
                    'content': """Config file will be downloaded"""
				},
                {
                    'code': 201,
                    'content': """{
    "message": "There is no new config file"
}"""
                }
            ],
            'error':[
                {
                    'code': 404,
                    'content': """{ 
    "error": "There is no config file. Request admin to upload config file" 
}"""
				},
                {
                   	'code': 403,
                    'content': """{ 
	"error": "You have to login First" 
}"""
				}
			],
		},
        'example': """
        import requests
        import json

        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'
        fetch_config_file_url = '/api/v1/config/fetch'


        session = requests.Session()

        data = {"email":"email", "password":"password"}

        response = session.post(host + login_url, data=data)

        if(response.ok) :
            print("Success")
            print("Content : "+response.content.decode())
            print("Status Code : " + str(response.status_code))
            data = {
                'md5sum':'b6a6f0b6bca855a20d5dde3c218c9e06',
            }
            response = session.get(host + fetch_config_file_url, params=data)
            if(response.status_code == 200) :
                print("Download Success")
                path = "config.ini"
                with open(path, 'wb') as f :
                    content = response.content
                    f.write(content)
                print("file : "+path)
                print("Status Code : " + str(response.status_code))
            elif(response.status_code == 201):
                print("There is no new config file on the server")
                print("Status Code : " + str(response.status_code))
            else :
                print("Get config download Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))

            response = session.get(host + logout_url)
            if(response.ok) :
                print("Logout Success")
                print("Content : "+response.content.decode())
                print("Status Code : " + str(response.status_code))
            else :
                print("Logout Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))
        else :
            print("Login Failure")
            print("Content : "+ response.content.decode())
            print("Status Code : " + str(response.status_code))
    """
	}

def getRoutineOptionsApi():
	return {
		'title': "Get routine options settings ",
        'url': "/api/v1/routine",
        'description': "This api get the routine options settings",
        'method': "GET",
        'header': """{ 
    Cookie: '<cookie_name>=CookieFromLoginResponse' 
}""",
        'response':{
            'success':[
                {
                    'code': 200,
                    'content': """{
   "fullDiskScan": true/false,
   "memoryScan": true/false    
}"""
				}
            ],
            'error':[
                {
                   	'code': 403,
                    'content': """{ 
	"error": "You have to login First" 
}"""
				}
			],
		},
        'example': """
        import requests
        import json

        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'
        get_routine_options_url = '/api/v1/routine'


        session = requests.Session()

        data = {"email":"email", "password":"password"}

        response = session.post(host + login_url, data=data)

        if(response.ok) :
            print("Success")
            print("Content : "+response.content.decode())
            print("Status Code : " + str(response.status_code))
            response = session.get(host + get_routine_options_url)
            if(response.status_code == 200) :
                print("Get routine options Success")
                print("Routine Options: "+response.content.decode())
                print("Status Code : " + str(response.status_code))
            else :
                print("Get alerts Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))

            response = session.get(host + logout_url)
            if(response.ok) :
                print("Logout Success")
                print("Content : "+response.content.decode())
                print("Status Code : " + str(response.status_code))
            else :
                print("Logout Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))
        else :
            print("Login Failure")
            print("Content : "+ response.content.decode())
            print("Status Code : " + str(response.status_code))
    """
	}


def getDownloadRuleApi():
	return {
		'title': "Export All signature rule",
        'url': "/api/v1/export/all",
        'description': "This is Export All signature rule endpoint.",
        'method': "GET",
        'header': """{ 
    Cookie: '<cookie_name>=CookieFromLoginResponse' 
}""",
        'response':{
            'success':[
                {
                    'code': 200,
                    'content': """File will be downloaded forcefully"""
                }
            ],
            'error':[
                {
                    'code': 404,
                    'content': """ "Nothing To Download" """
                },
                {
                    'code': 404,
                    'content': """ "You have to login First" """
                }
            ]
        },
        'example': """
        import requests
        import json
        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'
        download_url = '/api/v1/export/all'


        session = requests.Session()

        data = {"email":"email", "password":"password"}

        response = session.post(host + login_url, data=data)

        if(response.ok) :
            print("Success")
            print("Content : "+response.content.decode())
            print("Status Code : " + str(response.status_code))

            response = session.get(host + download_url)
            if(response.ok) :
                print("Download Success")
                path = "all_rules.yar"
                with open(path, 'wb') as f :
                    content = response.content
                    f.write(content)
                print("file : "+path)
                print("Status Code : " + str(response.status_code))
            else :
                print("Download Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))

            response = session.get(host + logout_url)
            if(response.ok) :
                print("Logout Success")
                print("Content : "+response.content.decode())
                print("Status Code : " + str(response.status_code))
            else :
                print("Logout Failure")
                print("Content : "+ response.content.decode())
                print("Status Code : " + str(response.status_code))
        else :
            print("Login Failure")
            print("Content : "+ response.content.decode())
            print("Status Code : " + str(response.status_code))
    """
	}