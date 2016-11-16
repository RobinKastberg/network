from django import template
from django.utils.safestring import mark_safe

register = template.Library()

@register.simple_tag
def str_or_input(key, value):
	if value:
		return mark_safe("<input type='hidden' name='"+key+"' value='"+value+"' />" + value)
	else:
		return mark_safe('<input type="text" name="'+key+'"/>')
