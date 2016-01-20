from django.shortcuts import render
from django.shortcuts import redirect
from registration.utils import get_page


def export_view(request):
    if request.user.is_authenticated() and request.method == 'GET':
        from .models import Category, Rule, RuleString, MetaData
        from django.core.paginator import Paginator, EmptyPage, PageNotAnInteger
        rule_delete = request.GET.get('delete')
        if rule_delete and request.user.metadata.role_id == 1:
            rule_delete = int(rule_delete)
            try:
                rule = Rule.objects.get(pk=rule_delete)
                rule.condition_rule.all().delete()
                rule.string_rule.all().delete()
                rule.meta_rule.all().delete()
                rule.delete()
            except:
                pass
        title = request.GET.get('title')
        category = request.GET.get('category')
        page_number = request.GET.get('page_number')
        page_size = request.GET.get('page_size')

        if not title:
            title = ""
        if not page_number:
            page_number = 1
        if not page_size:
            page_size = 10

        rule_list = Rule.objects.filter(name__icontains=title).order_by('-updated_at')

        if len(title):
            rule_result = rule_list
            rule_list = []
            for rule in rule_result:
                rule_list.append(rule)
            search_rows = RuleString.objects.filter(value__icontains=title)
            for row in search_rows:
                rule_list.append(row.rule)
            search_rows = MetaData.objects.filter(value__icontains=title)
            for row in search_rows:
                rule_list.append(row.rule)
            rule_list = list({v.rule_id: v for v in rule_list}.values())
            rule_list = sorted(rule_list, key=lambda k: k.updated_at, reverse=True)

        if category and category != "0":
            category = int(category)
            rule_result = []
            for rule in rule_list:
                if rule.category_id == category:
                    rule_result.append(rule)
            rule_list = rule_result

        rule_count = len(rule_list)
        first_rule = int(page_number) * int(page_size) - int(page_size) + 1
        paginator = Paginator(rule_list, page_size)
        try:
            rules = paginator.page(page_number)
        except PageNotAnInteger:
            rules = paginator.page(1)
        except EmptyPage:
            rules = paginator.page(paginator.num_pages)
        return render(request, 'rule-export.html', {'rules': rules, 'first_rule': first_rule, 'rule_count': rule_count, 'title':title, 'categories': Category.objects.all(), 'category': category, 'page': get_page('rule-export')})
    return redirect('index')


def import_view(request):
    if request.user.is_authenticated() and request.method == 'GET':
        from .forms import ImportFile
        from .models import Category
        form = ImportFile(initial={'source':""})
        return render(request, 'rule-import.html', {'form': form, 'categories': Category.objects.all(), 'page': get_page('rule-import')})
    elif request.user.is_authenticated() and request.method == 'POST':
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
                    form.fields.source = ""
                    form.fields.category = 0
                    if check:
                        form.add_error(None, 'Successfully import rule file')
                    else:
                        form.add_error(None, 'No rule in file to import')
            except:
                transaction.rollback()
                form.add_error(None, 'Unable to import Rule file')
        else:
            return render(request, 'rule-import.html', {'form': form, 'categories': Category.objects.all(), 'page': get_page('rule-import')})
        return render(request, 'rule-import.html', {'form': form, 'categories': Category.objects.all(), 'page': get_page('rule-import')})
    return redirect('index')


def export_rule(request, rule_id):
    if request.user.is_authenticated():
        try:
            from .models import Rule
            from . import rule_parser
            from django.http import HttpResponse
            rule = Rule.objects.get(pk=rule_id)
            rule_object = rule_parser.export_single_rule(rule)
            response = HttpResponse(rule_object, content_type='text/plain')
            response['Content-Disposition'] = 'attachment; filename="{0}.yar"'.format(rule.name.replace(' ', '_'))
            return response
        except:
            return redirect('index')
    return redirect('index')


def export_category(request, category_id):
    if request.user.is_authenticated():
        from . import rule_parser
        from django.http import HttpResponse
        if category_id == '0':
            rule_data = rule_parser.export_all_rule()
            if len(rule_data):
                response = HttpResponse(rule_data, content_type='text/plain')
                response['Content-Disposition'] = 'attachment; filename="all_rules.yar"'
                return response
            redirect('index')
        try:
            from .models import Category
            category = Category.objects.get(pk=category_id)
            category_rule_data = rule_parser.export_category_rule(category)
            if len(category_rule_data):
                response = HttpResponse(category_rule_data, content_type='text/plain')
                response['Content-Disposition'] = 'attachment; filename="{0}.yar"'.format(category.name.replace(' ', '_'))
                return response
        except:
            return redirect('index')
    return redirect('index')


def rule_view(request, rule_id):
    if request.user.is_authenticated():
        try:
            from .models import Rule
            rule = Rule.objects.get(pk=rule_id)
        except:
            return redirect('export')
        if request.method == 'POST' and request.user.metadata.role_id < 3:
            status = request.POST.get('status')
            if status == "0":
                rule.status = False
                # rule.version += 1
                rule.save()
            elif status == "1":
                rule.status = True
                # rule.version += 1
                rule.save()
        return render(request, 'rule-detail.html', {'rule': rule, 'page': get_page('rule-detail')})
    return redirect('index')

