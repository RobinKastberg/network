from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
import random
import logging
import ipaddress

logger = logging.getLogger(__name__)

# Create your views here.
def ipstr(ip):
	return str((ip >> 24) & 0xff)+"."+ str((ip >> 16) & 0xff)+"."+ str((ip >> 8) & 0xff)+"." + str(ip & 0xff)
def strip(ip):
	lst = ip.split(".")
	ip = (int(lst[0]) << 24)|(int(lst[1]) << 16)|(int(lst[2]) << 8)|(int(lst[3]))
	return ip
def check(dct):
	ip = strip(dct['ip'])
	ip2 = strip(dct['ip2'])
	gateway = strip(dct['gateway'])
	gateway2 = strip(dct['gateway2'])
	netmask = strip(dct['netmask'])
	netmask2 = strip(dct['netmask2'])
	if gateway != gateway2:
		return "Det måste vara samma gateway!"
	if (ip & netmask) != (ip2 & netmask2):
		return "IP-addresserna måste ha samma nätdel"
	if ip == ip2:
		return "IP-addresserna får inte vara lika"
	if ip == gateway:
		return "IP-addresserna får inte vara lika"
	if ip == gateway2:
		return "IP-addresserna får inte vara lika"
	if ip2 == gateway:
		return "IP-addresserna får inte vara lika"
	if ip2 == gateway2:
		return "IP-addresserna får inte vara lika"
	if ip & 0xff == 0 or ip & 0xff == 0xff:
		return "IP-addresser får inte sluta på 0 eller 255"
	if ip2 & 0xff == 0 or ip2 & 0xff == 0xff:
		return "IP-addresser får inte sluta på 0 eller 255"
	try:
		ipaddress.IPv4Network((ip & netmask, netmask))
		ipaddress.IPv4Network((ip2 & netmask2, netmask2))
	except:
		return "Något är fel med nätmask eller ip-addressen"
	return True
def index(request):
	ip = random.randrange(2**32)
	netmask = 0xffffff00
	gateway = (ip & netmask) | (~netmask & random.randrange(2**32))
	ip2 = (ip & netmask) | (~netmask & random.randrange(2**32))
	netmask2 = 0xffffff00
	gateway2 = gateway
	keys = ['ip', 'netmask', 'gateway', 'ip2', 'netmask2', 'gateway2']
	values = []
	del keys[random.randrange(len(keys))]
	del keys[random.randrange(len(keys))]
	for x in keys:
		values.append(ipstr(locals()[x]))
	return render(request, "exercise/question.html", dict(zip(keys, values)))
def validate(request):
	works = ""
	try:
		works = check(request.POST)
	except IndexError:
		works = "Du har skrivit fel någonstans"
	return JsonResponse({'response':works})
