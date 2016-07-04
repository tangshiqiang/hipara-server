from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.authentication import BasicAuthentication, SessionAuthentication
# from rest_framework.parsers import JSONParser, FileUploadParser


class CsrfExemptSessionAuthentication(SessionAuthentication):

    def enforce_csrf(self, request):
        return


class RuleManagerViewSet(viewsets.ViewSet):
    authentication_classes = (CsrfExemptSessionAuthentication, BasicAuthentication)
    # parser_classes = (JSONParser, FileUploadParser)

    def import_file(self, request, *args, **kwargs):
        result = {'data': "You have to login First", 'status': 403}
        if request.user.is_authenticated():
            if request.user.metadata.role_id != 4 :
                from .forms import ImportFile
                form = ImportFile(request.POST, request.FILES)

                if form.is_valid():
                    from django.db import transaction
                    parsed_rules = form.cleaned_data.get('rule_file')
                    category = form.cleaned_data.get('category'),
                    source = form.cleaned_data.get('source'),
                    user = request.user
                    try:
                        from .models import Condition, Rule, RuleString, MetaData

                        with transaction.atomic():
                            check = False
                            for rule_data in parsed_rules:
                                rule = Rule.objects.create(
                                    name=rule_data.get('name'),
                                    description="",
                                    category=category[0],
                                    source=source[0],
                                    created_by=user,
                                    updated_by=user
                                )
                                value = rule_data.get('value')
                                metas = value.get('meta')
                                for meta in metas:
                                    MetaData.objects.create(
                                        rule=rule,
                                        key=meta.get('key'),
                                        value=meta.get('value')
                                    )
                                strings = value.get('strings')
                                for string in strings:
                                    RuleString.objects.create(
                                        rule=rule,
                                        type=string.get('type'),
                                        name=string.get('name'),
                                        value=string.get('value'),
                                        is_nocase=string.get('is_nocase'),
                                        is_wide=string.get('is_wide'),
                                        is_full=string.get('is_full'),
                                        is_ascii=string.get('is_ascii')
                                    )
                                Condition.objects.create(
                                    rule=rule,
                                    condition=value.get('condition')
                                )
                                check = True
                            if check:
                                result = {'data': "Successfully import rule file", 'status': 200}
                            else:
                                result = {'data': "No rule in file to import", 'status': 422}
                    except:
                        transaction.rollback()
                        result = {'data': "Unable to import Rule file", 'status': 422}
                else:
                    result = {'data': form.errors, 'status': 422}
            else:
                result = {'data': "Not Allowed to Service User", 'status': 401}
        return Response(data=result['data'], status=result['status'])

    def export_all(self, request, *args, **kwargs):
        result = {'data': "You have to login First", 'status': 403}
        if request.user.is_authenticated():
            from . import rule_parser
            from django.http import HttpResponse
            rule_data = rule_parser.export_all_rule()
            if len(rule_data):
                response = HttpResponse(rule_data, content_type='text/plain')
                response['Content-Disposition'] = 'attachment; filename="all_rules.yar"'
                return response
            result = {'data': "Nothing To Download", 'status': 404}
        return Response(data=result['data'], status=result['status'])
