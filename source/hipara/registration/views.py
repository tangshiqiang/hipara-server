from django.shortcuts import render
from django.shortcuts import redirect


def index_view(request):
    return render(request, 'index.html')


def about_view(request):
    return render(request, 'about.html')


def apis_view(request):
    return render(request, 'apis.html')


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
                    form.add_error(None, "This account has been disabled")
            else:
                form.add_error(None, "Invalid Username and/or Password")
                form.fields.password = ""
    else:
        form = LoginForm(initial={'email': ""})
    return render(request, 'login.html', {'form': form})


def logout_view(request):
    if request.user.is_authenticated():
        from django.contrib.auth import logout
        logout(request)
    return redirect('index')


def users_view(request):
    if request.user.is_authenticated() and request.user.metadata.role_id < 3:

        from django.contrib.auth.models import User
        from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger

        page_number = request.GET.get('page_number')
        page_size = request.GET.get('page_size')

        if not page_number:
            page_number = 1
        if not page_size:
            page_size = 10
        users = []

        user_result = User.objects.filter(is_active=True, id__gt=request.user.id)

        users = user_result

        user_count = len(users)
        first_user = int(page_number) * int(page_size) - int(page_size) + 1
        last_user = int(page_number) * int(page_size)
        paginator = Paginator(users, page_size)
        try:
            users = paginator.page(page_number)
        except PageNotAnInteger:
            users = paginator.page(1)
        except EmptyPage:
            users = paginator.page(paginator.num_pages)
        return render(request, 'users.html',
                      {'users': users, 'first_user': first_user, 'last_user': last_user, 'user_count': user_count})
    return redirect('index')


def invite_view(request):
    if request.user.is_authenticated() and request.method == 'GET':
        if request.user.metadata.role_id == 1:
            from .models import User_invite_token
            if request.GET.get('delete'):
                User_invite_token.objects.filter(id=request.GET.get('delete')).delete()
                return redirect('invite')
            if request.GET.get('generate'):
                from datetime import datetime, timedelta
                import string, random
                token = ''.join(random.sample(string.ascii_lowercase, 25))
                expiry_date = datetime.now()+timedelta(days=1)
                User_invite_token.objects.create(
                    token=token,
                    expiry_date=expiry_date,
                    created_by=request.user
                )
                return redirect('invite')
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
            first_invite = int(page_number) * int(page_size) - int(page_size) + 1
            last_invite = int(page_number) * int(page_size)
            paginator = Paginator(invites, page_size)
            try:
                invites = paginator.page(page_number)
            except PageNotAnInteger:
                invites = paginator.page(1)
            except EmptyPage:
                invites = paginator.page(paginator.num_pages)
            return render(request, 'invite.html', {'invites': invites, 'first_invite': first_invite, 'last_invite': last_invite, 'invite_count': invite_count})
        else:
            return render(request, 'invite.html', {'emails': ""})
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
                    form = SignUpForm(
                        initial={'email': invite.email,
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
        return render(request, 'register.html', {'form': form, 'token': token, 'error': error})
    return redirect('index')


def notfound(request):
    return redirect('index')


def users_detail_view(request, id):
    from django.contrib.auth.models import User
    return render(request, 'user-detail.html', {'user_detail': User.objects.get(pk=id)})











def profile_update_view(request):
    if request.user.is_authenticated():
        from django.contrib.auth import logout
        logout(request)
    return redirect('index')
















# def register(request, token):
#     is_authenticated = request.user.is_authenticated()
#     template = 'error.html'
#     data = {'error': "404 Page not Found"}
#     if request.method == 'GET' and not is_authenticated:
#         try:
#             from django.contrib.auth.models import User
#             from django.utils import timezone
#             from .models import User_invite_token
#             invite = User_invite_token.objects.get(token=token)
#             if invite.expiry_date >= timezone.now():
#                 from .forms import SignUpForm
#                 form = SignUpForm(
#                     initial={'email': invite.email}
#                 )
#                 template = 'register.html'
#                 data = {'form': form, 'token': token}
#             else:
#                 invite.delete()
#                 data['error'] = "Sorry This Invite is Expired"
#         except:
#             data['error'] = "Sorry You are not Invited"
#     return return_response(request, template, data)
#
#
# def sign_up(request, token):
#     is_authenticated = request.user.is_authenticated()
#     template = 'error.html'
#     data = {'error': "404 Page not Found"}
#     if request.method == 'POST' and not is_authenticated:
#         email = request.POST.get('email')
#         try:
#             from django.utils import timezone
#             from .models import User_invite_token
#             invite = User_invite_token.objects.get(token=token)
#             if (not invite.email or invite.email == email) and invite.expiry_date >= timezone.now():
#                 from .forms import SignUpForm
#                 form = SignUpForm(request.POST)
#                 if form.is_valid():
#                     try:
#                         from django.contrib.auth.models import User
#                         from django.contrib.auth.hashers import make_password
#                         from django.contrib.auth import authenticate, login
#                         from django.shortcuts import redirect
#                         from .models import UserMetaData
#                         form = form.cleaned_data
#                         user = User.objects.create(
#                             username=form.get('username'),
#                             first_name=form.get('first_name'),
#                             last_name=form.get('last_name'),
#                             password=make_password(form.get('password')),
#                             email=form.get('email')
#                         )
#                         UserMetaData.objects.create(
#                             user=user,
#                             role_id=3,
#                             created_by=user,
#                             updated_by=user
#                         )
#                         if invite.email:
#                             invite.delete()
#                         user = authenticate(username=form.get('username'), password=form.get('password'))
#                         login(request, user)
#                         return redirect('index')
#                     except:
#                         data['error'] = "Some Error Occurred"
#                 else:
#                     template = 'register.html'
#                     data = {'form': form, 'token': token}
#             else:
#                 if invite.expiry_date < timezone.now():
#                     invite.delete()
#                 data['error'] = "Invite is Expired or invalid invite"
#         except:
#             data['error'] = "Sorry You are not Invited"
#     return return_response(request, template, data)
#
#
# def notfound(request):
#     return return_response(request, 'error.html', {'error': "404 Page Not Found"})
#
#
# # Login Page
# def login_page(request):
#     template = 'index.html'
#     data = {'error': "Unable to login to the Web Panel"}
#     if not request.user.is_authenticated():
#         try:
#             username = request.POST.get('username')
#             password = request.POST.get('password')
#             if username and password:
#                 from django.contrib.auth import authenticate, login
#                 user = authenticate(username=username, password=password)
#                 if user is not None:
#                     if user.is_active and not user.metadata.deleted_at:
#                         login(request, user)
#                         data = get_index(request)[1]
#                         from django.shortcuts import redirect
#                         return redirect('index')
#                     else:
#                         data['error'] = "This account has been disabled"
#                 else:
#                     data['error'] = "Invalid Username and/or Password"
#         except:
#             data['error'] = "Unable to login to the Web Panel"
#     else:
#         data = get_index(request)
#     return return_response(request, template, data)
#
#
# # Logout Page
# def logout_page(request):
#     template = 'index.html'
#     data = {'error': "You have to login first"}
#     if request.user.is_authenticated():
#         from django.contrib.auth import logout
#         logout(request)
#         data['error'] = "Logout Successful"
#     return return_response(request, template, data)
#
#
# def get_index(request):
#     from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
#     from rule_manager.models import Rule
#     from rule_manager.forms import ImportFile
#     import_file_form = ImportFile()
#     page = request.GET.get('page')
#     if not page:
#         page = 1
#     page_count = request.GET.get('count')
#     if not page_count:
#         page_count = 10
#     rule_list = Rule.objects.all()
#     rule_count = rule_list.count
#     first_rule = int(page) * int(page_count) - int(page_count) + 1
#     last_rule = int(page) * int(page_count)
#     paginator = Paginator(rule_list, page_count)
#     try:
#         rules = paginator.page(page)
#     except PageNotAnInteger:
#         rules = paginator.page(1)
#     except EmptyPage:
#         rules = paginator.page(paginator.num_pages)
#     return ['index.html', {'rule_list': rules, 'rule_count': rule_count, 'rules': [first_rule, last_rule], 'importFile': import_file_form}]
#
#
# def return_response(request, template, data={}):
#     response_data = {'error': ""}
#     if request.user.is_authenticated():
#         from rule_manager.models import Category
#         from rule_manager.models import Rule
#
#         response_data = {'total_rule_count': len(Rule.objects.all()), 'cat_list': Category.objects.all(), 'error': ""}
#     response_data.update(data)
#     from django.shortcuts import render
#     return render(request, template, response_data)
#
#
# def invite_page(request):
#     if request.user.is_authenticated():
#         return notfound(request)
#     else:
#         return notfound(request)
