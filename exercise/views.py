from django.shortcuts import render
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect
import random
import logging
import ipaddress

logger = logging.getLogger(__name__)

levels = {
		0: {'variable_netmask': False, 'subnetting': False, 'unknowns': 1},
		1: {'variable_netmask': False, 'subnetting': False, 'unknowns': 2},
		2: {'variable_netmask': False, 'subnetting': False, 'unknowns': 3},
		3: {'variable_netmask': True,  'subnetting': False, 'unknowns': 1},
		4: {'variable_netmask': True,  'subnetting': False, 'unknowns': 2},
		5: {'variable_netmask': True,  'subnetting': False, 'unknowns': 3},
		6: {'variable_netmask': True,  'subnetting': True,  'unknowns': 1},
		7: {'variable_netmask': True,  'subnetting': True,  'unknowns': 2},
		8: {'variable_netmask': True,  'subnetting': True,  'unknowns': 3},
		9: {'variable_netmask': True,  'subnetting': True,  'unknowns': 4},
		10:{'variable_netmask': True,  'subnetting': True,  'unknowns': 5},
		}
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
	netid = strip(dct['netid'])
	netid2 = strip(dct['netid2'])
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
	if (ip & netid) != netid:
		return "Fel Nät-ID"
	if (ip2 & netid2) != netid2:
		return "Fel Nät-ID"
	if (gateway & netid) != netid:
		return "Gateway måste ligga på det lokala nätverket"
	if (gateway2 & netid2) != netid2:
		return "Gateway måste ligga på det lokala nätverket"
	if netid != netid2:
		return "Nät-ID måste vara samma."
	try:
		ipaddress.IPv4Network((ip & netmask, netmask))
		ipaddress.IPv4Network((ip2 & netmask2, netmask2))
	except:
		return "Något är fel med nätmask eller ip-addressen"
	return True
def generate_netmask(variable=False, subnet=False):
	if variable:
		if subnet:
			shift = 1+random.randrange(31)	
		else:
			shift = 8*(1+random.randrange(3))
	else:
		shift = 8

	return (0xffffffff << shift) & 0xffffffff

def index(request):
	if not 'level' in request.session:
		request.session['level'] = 0
	if not 'streak' in request.session:
		request.session['streak'] = 0
	level = levels[request.session['level']]
	ip = random.randrange(2**32)
	netmask = generate_netmask(level['variable_netmask'], level['subnetting'])
	gateway = (ip & netmask) | (~netmask & random.randrange(2**32))
	ip2 = (ip & netmask) | (~netmask & random.randrange(2**32))
	netmask2 = netmask
	netid = (ip & netmask)
	netid2 = (ip2 & netmask2)
	gateway2 = gateway
	keys = ['ip', 'netmask', 'gateway', 'ip2', 'netmask2', 'gateway2', 'netid', 'netid2']
	values = []
	allkeys = list(keys)
	allvalues = []
	for x in allkeys:
		allvalues.append(ipstr(locals()[x]))
	for i in range(level['unknowns']):
		del keys[random.randrange(len(keys))]
	for x in keys:
		values.append(ipstr(locals()[x]))

	if not check(dict(zip(allkeys, allvalues))) == True:
		return index(request)
	return render(request, "exercise/question.html", {**dict(zip(keys, values)),**{'streak': request.session['streak'], 'level': request.session['level']}})
def restart(request):
	if 'level' in request.session:
		del request.session['level']
	if 'streak' in request.session:
		del request.session['streak']
	return HttpResponseRedirect(request.META.get('HTTP_REFERER'))
def validate(request):
	works = ""
	try:
		works = check(request.POST)
	except IndexError:
		works = "Du har skrivit fel någonstans"
	except ValueError:
		works = "Du har skrivit fel någonstans"
	if works == True:
		request.session['streak'] += 1
		if request.session['streak'] > 0 and request.session['streak'] % 3 == 0:
			request.session['level'] += 1
	else:
		request.session['streak'] = 0
	return JsonResponse({'response':works})
