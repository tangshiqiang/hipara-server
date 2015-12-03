# from django.db import transaction
from django.shortcuts import render, redirect
from django.http import HttpResponse, Http404
from .models import Rule, MetaData, RuleString, Condition, Category
from registration.views import return_response
from . import rule_parser


def search(request):
    if not request.user.is_authenticated():
        error_line = "You need to be logged in to perform that action"
        return render(request, 'error.html', {'error': error_line})
    try:
        search_type = request.GET['search_type']
        search_word = request.GET['search_word']
    except:
        return return_response(request, 'search.html',{'search_type': '', 'search_word': ''})
    if search_type == 'name':
        rule_list = Rule.objects.filter(name__contains=search_word)
    elif search_type == 'string':
        search_rows = RuleString.objects.filter(value__contains=search_word)
        rule_list = []
        for row in search_rows:
            rule_list.append(row.rule)
    elif search_type == 'meta':
        search_rows = MetaData.objects.filter(value__contains=search_word)
        rule_list = []
        for row in search_rows:
            rule_list.append(row.rule)
    else:
        error_line = "Not a valid Search"
        return render(request, 'error.html', {'error': error_line})


    from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
    page = request.GET.get('page')
    if not page:
        page = 1
    page_count = request.GET.get('count')
    if not page_count:
        page_count = 10
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
    return return_response(request, 'search.html', {'rule_list': rules, 'rule_count': rule_count, 'rules': [first_rule, last_rule], 'search_type': search_type, 'search_word': search_word,})


def import_rules(request):
    from registration.views import get_index
    data = get_index(request)[1]
    if request.method == 'POST' and request.user.is_authenticated():
        from .forms import ImportFile
        import_file_form = ImportFile(request.POST, request.FILES)
        if import_file_form.is_valid():
            import_file_form = import_file_form.cleaned_data
            parsed_rules = import_file_form.get('rule_file')
            user = request.user
            try:
                from django.db import transaction
                with transaction.atomic():
                    check = False
                    for rule_data in parsed_rules:
                        rule = Rule.objects.create(
                            name=rule_data.get('name'),
                            description="",
                            category=import_file_form.get('category'),
                            source=import_file_form.get('source'),
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
                        return redirect('/')

            except:
                transaction.rollback()
                import_file_form.add_error('rule_file', 'Unable to save Rule file')
                data.update({'importFile': import_file_form})
        else:
            data.update({'importFile': import_file_form})
    return return_response(request, 'index.html', data)


def export_rule(request, rule_id):
    if not request.user.is_authenticated():
        error_line = "You need to be logged in to perform that action"
        return return_response(request, 'error.html', {'error': error_line})
    try:
        rule = Rule.objects.get(pk=rule_id)
        rule_object = rule_parser.export_single_rule(rule)
        response = HttpResponse(rule_object, content_type='text/plain')
        response['Content-Disposition'] = 'attachment; filename="{0}.yar"'.format(rule.name.replace(' ', '_'))
        return response
    except:
        error_line = "Invalid rule for export"
        return return_response(request, 'error.html', {'error': error_line})


def export_category(request, category_id):
    error_line = "You need to be logged in to perform that action"
    if request.user.is_authenticated():
        try:
            category = Category.objects.get(pk=category_id)
            category_rule_data = rule_parser.export_category_rule(category)
            if len(category_rule_data):
                response = HttpResponse(category_rule_data, content_type='text/plain')
                response['Content-Disposition'] = 'attachment; filename="{0}.yar"'.format(category.name.replace(' ', '_'))
                return response
            error_line = "No rule in Category '{0}' to export".format(category.name)
        except:
            error_line = "Invalid category for export"
    return return_response(request, 'error.html', {'error': error_line})


def export_all(request):
    error_line = "You need to be logged in to perform that action"
    if request.user.is_authenticated():
        rule_data = rule_parser.export_all_rule()
        if len(rule_data):
            response = HttpResponse(rule_data, content_type='text/plain')
            response['Content-Disposition'] = 'attachment; filename="all_rules.yar"'
            return response
        error_line = "No rule in database to export"

    return return_response(request, 'error.html', {'error': error_line})


def rule_view(request, rule_id):
    error_line = "You need to be logged in to perform that action"
    if request.user.is_authenticated():
        try:
            rule = Rule.objects.get(pk=rule_id)
            meta_list = rule.meta_rule.all()
            string_list = rule.string_rule.all()
            condition = rule.condition_rule.all()[0]
            if request.method == 'GET':
                return return_response(request, 'rule.html', {'rule_details': rule, 'meta_list':meta_list, 'string_list': string_list, 'condition': condition, 'string_types':['String', 'Hex', 'RegEx']})
            elif request.method == 'POST' and request.POST.get('action') == 'update':
                try:
                    rule.version += 1
                    rule.save()

                    #meta data
                    meta_ids = request.POST.getlist('meta_id')
                    meta_values = request.POST.getlist('metaValues')
                    meta_keys = request.POST.getlist('metaKeys')
                    condition_value = request.POST.get('conditionValue')
                    meta_save = []
                    for i in range(len(meta_values)):
                        if meta_ids[i] == 'new':
                            meta_data = MetaData()
                            meta_data.rule = rule
                        else:
                            meta_data = MetaData.objects.get(pk=meta_ids[i])
                        meta_data.key = meta_keys[i]
                        meta_data.value = meta_values[i]
                        meta_data.save()
                        meta_save.append(meta_data.id)

                    # Delete Rows
                    for obj in meta_list:
                        if obj.id not in meta_save:
                            MetaData.objects.filter(pk=obj.id).delete()

                    # Strings
                    string_ids = request.POST.getlist('string_id')
                    string_names = request.POST.getlist('stringName')
                    string_values = request.POST.getlist('stringValues')
                    string_nocases = request.POST.getlist('caseValues')
                    string_wides = request.POST.getlist('wideValues')
                    string_fulls = request.POST.getlist('fullValues')
                    string_asciis = request.POST.getlist('asciiValues')

                    # Collect the string vars
                    string_save = []
                    for i in range(len(string_names)):
                        if string_ids[i] == 'new':
                            rule_strings = RuleString()
                            rule_strings.rule = rule
                        else:
                            rule_strings = RuleString.objects.get(pk=string_ids[i])

                        rule_strings.name = string_names[i]
                        rule_strings.value = string_values[i]
                        print(string_nocases[i])
                        rule_strings.is_nocase = True if string_nocases[i] == '1' else False
                        rule_strings.is_wide = True if string_wides[i] == '1' else False
                        rule_strings.is_full = True if string_fulls[i] == '1' else False
                        rule_strings.is_ascii = True if string_asciis[i] == '1' else False
                        rule_strings.save()
                        string_save.append(rule_strings.id)

                    # Delete Rows
                    for obj in string_list:
                        if obj.id not in string_save:
                            RuleString.objects.filter(pk=obj.id).delete()
                    condition.condition = condition_value
                    condition.save()

                    return redirect('/rule/{0}/'.format(rule_id))
                except:
                    error_line = "Some Error occured while saving rule : {0}".format(rule.name)
            elif request.method == 'POST' and request.POST.get('action') == 'delete':
                condition.delete()
                string_list.delete()
                meta_list.delete()
                rule.delete()
                return redirect('index')
            else:
                error_line = "Unable to process request"
        except:
            error_line = "Invalid Rule"
    return return_response(request, 'error.html', {'error': error_line})
