from django.shortcuts import render
from django.shortcuts import redirect
from .utils import get_page


def index_view(request):
    return render(request, 'index.html', {'page': get_page('index')})


def about_view(request):
    return render(request, 'about.html', {'page': get_page('about')})


def apis_view(request):
    return render(request, 'apis.html', {'page': get_page('apis')})


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
                    login(request, user)
                    return redirect('index')
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
            if user.metadata.role_id > request.user.metadata.role_id:
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
                roles = Role.objects.filter(role_id__gt=1)
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
