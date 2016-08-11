from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.authentication import BasicAuthentication, SessionAuthentication


class CsrfExemptSessionAuthentication(SessionAuthentication):

    def enforce_csrf(self, request):
        return


class AuthenticationViewSet(viewsets.ViewSet):
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)

    def login(self, request, *args, **kwargs):
        if request.user.is_authenticated():
            result = {'data': "Already Logged In", 'status': 200}
        else :
            from .forms import LoginForm
            form = LoginForm({'email':request.data.get('email'),'password':request.data.get('password')})
            result = {'data': "", 'status': 422}
            if form.is_valid():
                from django.contrib.auth import authenticate, login
                user = authenticate(username=form.cleaned_data.get('email'), password=form.cleaned_data.get('password'))
                if user is not None:
                    if user.is_active and not user.metadata.deleted_at:
                        login(request, user)
                        result['data'] = "Login Successful"
                        result['status'] = 200
                    else:
                        result['data'] = "This account has been disabled contact to admin"
                        result['status'] = 403
                else:
                    result['data'] = "Invalid Username and/or Password"
            else:
                result['data'] = form.errors
        return Response(data=result['data'], status=result['status'])

    def logout(self, request, *args, **kwargs):
        result = {'data': "You have to login First", 'status': 403}
        if request.user.is_authenticated():
            from django.contrib.auth import logout
            logout(request)
            result = {'data': "Logout successful", 'status': 200}
        return Response(data=result['data'], status=result['status'])

