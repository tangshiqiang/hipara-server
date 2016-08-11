
def get_page(page):
    try:
        import re
        from collections import OrderedDict
        from django.conf import settings
        page = open(settings.BASE_DIR + '/pages/' + page + ".md").read()
        line = re.compile(r'( *)- ([^:\n]+)(?:: ([^\n]*))?\n?')
        depth = 0
        stack = [OrderedDict()]
        for indent, name, value in line.findall(page):
            indent = len(indent)
            if indent > depth:
                assert not stack[-1], 'unexpected indent'
            while indent < depth:
                stack.pop()
                depth -= 4
            stack[-1][name] = value or OrderedDict()
            if not value:
                stack.append(stack[-1][name])
            depth = indent
        return stack[0]
    except:
        return OrderedDict()