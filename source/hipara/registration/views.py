

def register(request, token):
    is_authenticated = request.user.is_authenticated()
    template = 'error.html'
    data = {'error': "404 Page not Found"}
    if request.method == 'GET' and not is_authenticated:
        try:
            from django.contrib.auth.models import User
            from django.utils import timezone
            from .models import User_invite_token
            invite = User_invite_token.objects.get(token=token)
            if invite.expiry_date >= timezone.now():
                from .forms import SignUpForm
                form = SignUpForm(
                    initial={'email': invite.email}
                )
                template = 'register.html'
                data = {'form': form, 'token': token}
            else:
                invite.delete()
                data['error'] = "Sorry This Invite is Expired"
        except:
            data['error'] = "Sorry You are not Invited"
    return return_response(request, template, data)


def sign_up(request, token):
    is_authenticated = request.user.is_authenticated()
    template = 'error.html'
    data = {'error': "404 Page not Found"}
    if request.method == 'POST' and not is_authenticated:
        email = request.POST.get('email')
        try:
            from django.utils import timezone
            from .models import User_invite_token
            invite = User_invite_token.objects.get(token=token)
            if (not invite.email or invite.email == email) and invite.expiry_date >= timezone.now():
                from .forms import SignUpForm
                form = SignUpForm(request.POST)
                if form.is_valid():
                    try:
                        from django.contrib.auth.models import User
                        from django.contrib.auth.hashers import make_password
                        from django.contrib.auth import authenticate, login
                        from django.shortcuts import redirect
                        from .models import UserMetaData
                        form = form.cleaned_data
                        user = User.objects.create(
                            username=form.get('username'),
                            first_name=form.get('first_name'),
                            last_name=form.get('last_name'),
                            password=make_password(form.get('password')),
                            email=form.get('email')
                        )
                        UserMetaData.objects.create(
                            user=user,
                            role_id=3,
                            created_by=user,
                            updated_by=user
                        )
                        if invite.email:
                            invite.delete()
                        user = authenticate(username=form.get('username'), password=form.get('password'))
                        login(request, user)
                        return redirect('index')
                    except:
                        data['error'] = "Some Error Occurred"
                else:
                    template = 'register.html'
                    data = {'form': form, 'token': token}
            else:
                if invite.expiry_date < timezone.now():
                    invite.delete()
                data['error'] = "Invite is Expired or invalid invite"
        except:
            data['error'] = "Sorry You are not Invited"
    return return_response(request, template, data)


def notfound(request):
    return return_response(request, 'error.html', {'error': "404 Page Not Found"})


# Login Page
def login_page(request):
    template = 'index.html'
    data = {'error': "Unable to login to the Web Panel"}
    if not request.user.is_authenticated():
        try:
            username = request.POST.get('username')
            password = request.POST.get('password')
            if username and password:
                from django.contrib.auth import authenticate, login
                user = authenticate(username=username, password=password)
                if user is not None:
                    if user.is_active and not user.metadata.deleted_at:
                        login(request, user)
                        data = get_index(request)[1]
                        from django.shortcuts import redirect
                        return redirect('index')
                    else:
                        data['error'] = "This account has been disabled"
                else:
                    data['error'] = "Invalid Username and/or Password"
        except:
            data['error'] = "Unable to login to the Web Panel"
    else:
        data = get_index(request)
    return return_response(request, template, data)


# Logout Page
def logout_page(request):
    template = 'index.html'
    data = {'error': "You have to login first"}
    if request.user.is_authenticated():
        from django.contrib.auth import logout
        logout(request)
        data['error'] = "Logout Successful"
    return return_response(request, template, data)


def get_index(request):
    from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
    from rule_manager.models import Rule
    page = request.GET.get('page')
    if not page:
        page = 1
    page_count = request.GET.get('count')
    if not page_count:
        page_count = 10
    rule_list = Rule.objects.all()
    rule_count = rule_list.count
    first_rule = int(page) * int(page_count) - int(page_count) + 1
    last_rule = int(page) * int(page_count)
    paginator = Paginator(rule_list, page_count)
    try:
        rules = paginator.page(page)
    except PageNotAnInteger:
        rules = paginator.page(1)
    except EmptyPage:
        rules = paginator.page(paginator.num_pages)
    return ['index.html', {'rule_list': rules, 'rule_count': rule_count, 'rules': [first_rule, last_rule]}]


# Main Page
def index_view(request):
    # print(request.GET.get('error'))
    # print("Hi")
    if request.user.is_authenticated():
        data = get_index(request)
    else:
        data = ['index.html', {}]
    return return_response(request, data[0], data[1])


def return_response(request, template, data={}):
    response_data = {'error': ""}
    if request.user.is_authenticated():
        from rule_manager.models import Category
        from rule_manager.models import Rule

        response_data = {'total_rule_count': len(Rule.objects.all()), 'cat_list': Category.objects.all(), 'error': ""}
    response_data.update(data)
    from django.shortcuts import render
    return render(request, template, response_data)


def invite_page(request):
    if request.user.is_authenticated():
        return notfound(request)
    else:
        return notfound(request)
