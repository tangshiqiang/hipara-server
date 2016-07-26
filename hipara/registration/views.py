from django.shortcuts import render
from django.shortcuts import redirect
from .utils import get_page


# def index_view(request):
#     return render(request, 'index.html', {'page': get_page('index')})

def index_view(request):
    if request.user.is_authenticated():
        if request.user.metadata.role_id == 1 or request.user.metadata.role_id == 2 :
            return render(request, 'alert.html', {'page': get_page('alert')})
        return apis_view(request)
    return login_view(request)


    if request.user.is_authenticated() :
        return apis_view(request)
    return login_view(request)


# def about_view(request):
#     return render(request, 'about.html', {'page': get_page('about')})

def about_view(request):
    return redirect('/')

def alert_view(request):
    if request.user.is_authenticated():
        if (request.user.metadata.role_id == 1 or request.user.metadata.role_id == 2) and request.method == 'GET':
            return render(request, 'alert.html', {'page': get_page('alert')})
    return redirect('/')

def apis_view(request):
    data = {
        'api1' : """
        import requests
        import json
        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'

        session = requests.Session()   # to manage cookies

        data = {"email":"username/email", "password":"password"}

        response = session.post(host + login_url, data=data)

        if(response.ok) :
            print("Login Success")
            print("Content : "+response.content.decode())
            print("Status Code : " + str(response.status_code))

        else :
            print("Login Failure")
            print("Content : "+ response.content.decode())
            print("Status Code : " + str(response.status_code))
    """,

    'api2' : """
        import requests
        import json
        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'


        session = requests.Session()

        data = {"email":"username/email", "password":"password"}

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
    """,

    'api3' : """
        import requests
        import json
        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'
        download_url = '/api/v1/export/all'


        session = requests.Session()

        data = {"email":"username/email", "password":"password"}

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
    """,

    'api4' : """
        import requests
        import json
        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'
        upload_url = '/api/v1/import'

        session = requests.Session()

        data = {"email":"username/email", "password":"password"}

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
    """,

    'api5' : """
        import requests
        import json
        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'
        store_alerts_url = '/api/v1/alerts'


        session = requests.Session()

        data = {"email":"username/email", "password":"password"}

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
    """,

    'api6' : """
        import requests
        import json

        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'
        get_alerts_url = '/api/v1/alerts'


        session = requests.Session()

        data = {"email":"username/email", "password":"password"}

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
    """,
    'api7' : """
        import requests
        import json
        host = 'http://localhost:8000'
        login_url = '/api/v1/auth/login'
        logout_url = '/api/v1/auth/logout'
        download_url = '/api/v1/export'


        session = requests.Session()

        data = {"email":"username/email", "password":"password"}

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
    """,

    }
    return render(request, 'apis.html', {'page': get_page('apis'), 'examples':data})



def login_view(request):
    from .forms import LoginForm
    if request.user.is_authenticated():
        return redirect('/')
    elif request.method == 'POST':
        form = LoginForm(request.POST)
        if form.is_valid():
            from django.contrib.auth import authenticate, login
            user = authenticate(username=form.cleaned_data.get('email'), password=form.cleaned_data.get('password'))
            if user is not None:
                if user.is_active and not user.metadata.deleted_at:
                    if user.metadata.role_id != 4 :
                        login(request, user)
                        return redirect('index')
                    else:
                        form.add_error(None, "UI login for Service user not allowed")
                else:
                    form.add_error(None, "This account has been disabled contact to admin")
            else:
                form.add_error(None, "Invalid Username and/or Password")
                form.fields.password = ""
    else:
        form = LoginForm(initial={'email': ""})
    return render(request, 'login.html', {'form': form, 'page': get_page('login')})


def logout_view(request):
    if request.user.is_authenticated():
        from django.contrib.auth import logout
        logout(request)
    return redirect('index')

def change_password_view(request):
    from .forms import ChangePasswordForm
    if request.user.is_authenticated() is None:
        return redirect('/')
    elif request.method == 'POST':
        form = ChangePasswordForm(request.POST, user=request.user)
        if form.is_valid():
            request.user.set_password(form.cleaned_data.get('new_password'))
            request.user.save()
            form.add_error(None, "Password Changed Successfully")
        form.fields.old_password = ""
        form.fields.new_password = ""
    else:
        form = ChangePasswordForm(initial={'old_password': ""})
    return render(request, 'change-password.html', {'form': form, 'page': get_page('change-password')})


def users_view(request):
    if request.user.is_authenticated() and request.user.metadata.role_id < 3:

        from django.contrib.auth.models import User
        from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
        from django.db.models import Q

        page_number = request.GET.get('page_number')
        page_size = request.GET.get('page_size')
        search = request.GET.get('search')
        if not page_number:
            page_number = 1
        if not page_size:
            page_size = 10
        if not search:
            search = ""
        users = []

        user_result = User.objects.filter(Q(first_name__icontains=search) | Q(last_name__icontains=search) | Q(email__icontains=search)).order_by('first_name')
        for user in user_result:
            if user.metadata.role_id > request.user.metadata.role_id and user.metadata.role_id != 4:
                users.append(user)

        user_count = len(users)
        paginator = Paginator(users, page_size)
        try:
            users = paginator.page(page_number)
        except PageNotAnInteger:
            users = paginator.page(1)
        except EmptyPage:
            users = paginator.page(paginator.num_pages)
        return render(request, 'users.html',
                      {'users': users, 'user_count': user_count, 'search': search, 'page': get_page('users')})
    return redirect('index')


def invite_view(request):
    if request.user.is_authenticated():
        from .models import User_invite_token
        if request.user.metadata.role_id == 1 and request.method == 'GET':
            if request.GET.get('delete'):
                User_invite_token.objects.filter(id=request.GET.get('delete')).delete()
            elif request.GET.get('generate'):
                from datetime import datetime, timedelta
                import string, random
                token = ''.join(random.sample(string.ascii_lowercase, 25))
                expiry_date = datetime.now()+timedelta(days=1)
                User_invite_token.objects.create(
                    token=token,
                    expiry_date=expiry_date,
                    created_by=request.user
                )
        error = ""
        if request.method == 'POST':
            emails = request.POST.get('emails')
            if not emails:
                emails = ""
            email_list = emails.split(',')
            if len(email_list):
                from django.core.mail import EmailMultiAlternatives
                from datetime import datetime, timedelta
                import string, random
                from django.core.urlresolvers import reverse

                error = ""
                expiry_date = datetime.now() + timedelta(days=1)
                for email in email_list:
                    try:
                        token = ''.join(random.sample(string.ascii_lowercase, 25))
                        user_invite_token = User_invite_token()
                        user_invite_token.token = token
                        user_invite_token.email = email
                        user_invite_token.expiry_date = expiry_date
                        user_invite_token.created_by = request.user
                        subject = "Invite From Hipara"
                        url = request.build_absolute_uri(reverse('register', kwargs={'token': token}))
                        html_body = 'Invite url : <a href="' + url + '">link</a>'
                        body = "Invite url : "+url
                        from_email = "Hipara Support <support@hipara.org>"
                        headers = {'Reply-To': 'Hipara Support <no-reply@hipara.org>'}
                        msg = EmailMultiAlternatives(subject=subject, body=body, from_email=from_email, to=[email], headers = headers)
                        msg.attach_alternative(html_body, "text/html")
                        msg.send()
                        user_invite_token.save()
                    except:
                        if not error:
                            error = "Following invites are unsuccessful : "
                        error += email + " "
                if not error:
                    error = "All Invites send successful"
            else:
                error = 'No email to send invite'
        if request.user.metadata.role_id == 1:
            from .models import User_invite_token
            from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

            page_number = request.GET.get('page_number')
            page_size = request.GET.get('page_size')

            if not page_number:
                page_number = 1
            if not page_size:
                page_size = 10

            invites = User_invite_token.objects.filter(email=None).order_by('-created_at')
            invite_count = len(invites)
            paginator = Paginator(invites, page_size)
            try:
                invites = paginator.page(page_number)
            except PageNotAnInteger:
                invites = paginator.page(1)
            except EmptyPage:
                invites = paginator.page(paginator.num_pages)
            return render(request, 'invite.html', {'invites': invites, 'invite_count': invite_count, 'error': error, 'page': get_page('invite')})
        else:
            return render(request, 'invite.html', {'error': error, 'page': get_page('invite')})
    return redirect('index')


def register_view(request, token):
    if not request.user.is_authenticated():
        from django.utils import timezone
        from .models import User_invite_token
        from .forms import SignUpForm
        form = SignUpForm(
            initial={'email': "",
                     'first_name': "",
                     'last_name': "",
                     'username': ""}
        )
        error = ""
        try:
            invite = User_invite_token.objects.get(token=token)
            if invite.expiry_date >= timezone.now():
                if request.method == 'GET':
                    email = ""
                    if invite.email:
                        email = invite.email
                    form = SignUpForm(
                        initial={'email': email,
                                 'first_name': "",
                                 'last_name': "",
                                 'username': ""}
                    )
                elif request.method == 'POST':
                    form = SignUpForm(request.POST)
                    if form.is_valid():
                        if not invite.email or invite.email == form.cleaned_data.get('email'):
                            from django.db import transaction
                            try:
                                from django.contrib.auth.models import User
                                from django.contrib.auth.hashers import make_password
                                from django.contrib.auth import authenticate, login
                                from .models import UserMetaData
                                with transaction.atomic():
                                    user = User.objects.create(
                                        username=form.cleaned_data.get('username'),
                                        first_name=form.cleaned_data.get('first_name'),
                                        last_name=form.cleaned_data.get('last_name'),
                                        password=make_password(form.cleaned_data.get('password')),
                                        email=form.cleaned_data.get('email')
                                    )
                                    UserMetaData.objects.create(
                                        user=user,
                                        role_id=3,
                                        created_by=invite.created_by,
                                        updated_by=user
                                    )
                                    if invite.email:
                                        invite.delete()
                                    user = authenticate(username=user.email, password=form.cleaned_data.get('password'))
                                    login(request, user)
                                    return redirect('index')
                            except:
                                transaction.rollback()
                                form.add_error(None, 'Some Error Occurred while Sign Up')
                        else:
                            form.add_error('email', 'Invalid Email for this Invite')
                else:
                    error = 'Unable to process request'
            else:
                error = 'This invite is Expired'
        except:
            error = "Sorry You are not Invited"
        return render(request, 'register.html', {'form': form, 'token': token, 'error': error, 'page': get_page('register')})
    return redirect('index')


def not_found(request):
    return redirect('index')


def users_detail_view(request, id):
    if request.user.is_authenticated() and request.user.metadata.role_id == 1:
        try:
            from django.contrib.auth.models import User
            from .models import Role
            user = User.objects.get(pk=id)
            if user.metadata.role_id > request.user.metadata.role_id:
                roles = Role.objects.filter(role_id__gt=1, role_id__lt=4)
                if request.method == 'GET':
                    return render(request, 'user-detail.html', {'user_detail': user, 'roles': roles, 'page': get_page('user-detail')})
                elif request.method == 'POST':
                    status = int(request.POST.get('status'))
                    role = int(request.POST.get('role'))
                    if role > 1:
                        user.is_active = status
                        metatadata = user.metadata
                        metatadata.role_id = role
                        metatadata.updated_by = request.user
                        user.save()
                        metatadata.save()
                        return render(request, 'user-detail.html', {'user_detail': user, 'roles': roles, 'page': get_page('user-detail')})
        except:
            return redirect('index')
    return redirect('index')
