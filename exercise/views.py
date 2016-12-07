# -*- coding: utf-8 -*-
from django.shortcuts import render
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.sessions.models import Session
from django.utils.html import escape
import random
import logging
import json

def merge_two_dicts(x, y):
    '''Given two dicts, merge them into a new dict as a shallow copy.'''
    z = x.copy()
    z.update(y)
    return z

logger = logging.getLogger(__name__)

levels = {
		0: {'variable_netmask': False, 'subnetting': False, 'unknowns': 1},
		1: {'variable_netmask': False, 'subnetting': False, 'unknowns': 2},
		2: {'variable_netmask': False, 'subnetting': False, 'unknowns': 3},
                3: {'variable_netmask': False, 'subnetting': False, 'unknowns': 4},
		4: {'variable_netmask': True,  'subnetting': False, 'unknowns': 1},
		5: {'variable_netmask': True,  'subnetting': False, 'unknowns': 2},
		6: {'variable_netmask': True,  'subnetting': False, 'unknowns': 3},
                7: {'variable_netmask': True,  'subnetting': False, 'unknowns': 4},
                8: {'variable_netmask': True,  'subnetting': False, 'unknowns': 5},
                9: {'variable_netmask': True,  'subnetting': False, 'unknowns': 6},
                10: {'variable_netmask': True,  'subnetting': False, 'unknowns': 7},
                11: {'variable_netmask': True,  'subnetting': False, 'unknowns': 8},
		12: {'variable_netmask': True,  'subnetting': True,  'unknowns': 1},
		13: {'variable_netmask': True,  'subnetting': True,  'unknowns': 2},
		14: {'variable_netmask': True,  'subnetting': True,  'unknowns': 3},
		15: {'variable_netmask': True,  'subnetting': True,  'unknowns': 4},
		16:{'variable_netmask': True,  'subnetting': True,  'unknowns': 5},
                17:{'variable_netmask': True,  'subnetting': True,  'unknowns': 6},
                18:{'variable_netmask': True,  'subnetting': True,  'unknowns': 7},
                19:{'variable_netmask': True,  'subnetting': True,  'unknowns': 8},
		}
levels2 = {
		0: {'variable_netmask': False, 'subnetting': False, 'unknowns': 1},
		1: {'variable_netmask': False, 'subnetting': False, 'unknowns': 2},
		2: {'variable_netmask': False, 'subnetting': False, 'unknowns': 3},
                3: {'variable_netmask': False, 'subnetting': False, 'unknowns': 4},
		4: {'variable_netmask': True,  'subnetting': False, 'unknowns': 1},
		5: {'variable_netmask': True,  'subnetting': False, 'unknowns': 2},
		6: {'variable_netmask': True,  'subnetting': False, 'unknowns': 3},
                7: {'variable_netmask': True,  'subnetting': False, 'unknowns': 4},
                8: {'variable_netmask': True,  'subnetting': False, 'unknowns': 5},
                9: {'variable_netmask': True,  'subnetting': False, 'unknowns': 6},
                10: {'variable_netmask': True,  'subnetting': False, 'unknowns': 7},
                11: {'variable_netmask': True,  'subnetting': False, 'unknowns': 8},
		12: {'variable_netmask': True,  'subnetting': True,  'unknowns': 1},
		13: {'variable_netmask': True,  'subnetting': True,  'unknowns': 2},
		14: {'variable_netmask': True,  'subnetting': True,  'unknowns': 3},
		15: {'variable_netmask': True,  'subnetting': True,  'unknowns': 4},
		16:{'variable_netmask': True,  'subnetting': True,  'unknowns': 5},
                17:{'variable_netmask': True,  'subnetting': True,  'unknowns': 6},
                18:{'variable_netmask': True,  'subnetting': True,  'unknowns': 7},
                19:{'variable_netmask': True,  'subnetting': True,  'unknowns': 8},
		}
# Create your views here.
def ipstr(ip):
	return str((ip >> 24) & 0xff)+"."+ str((ip >> 16) & 0xff)+"."+ str((ip >> 8) & 0xff)+"." + str(ip & 0xff)
def strip(ip):
	lst = ip.split(".")
	ip = (int(lst[0]) << 24)|(int(lst[1]) << 16)|(int(lst[2]) << 8)|(int(lst[3]))
	return ip
def check_two_networks(dct):
	ip = strip(dct['ip'])
	ip2 = strip(dct['ip2'])
	gateway = strip(dct['gateway'])
	gateway2 = strip(dct['gateway2'])
	netmask = strip(dct['netmask'])
	netmask2 = strip(dct['netmask2'])
	netid = strip(dct['netid'])
	netid2 = strip(dct['netid2'])
	router_left = strip(dct['router_left'])
	router_right = strip(dct['router_right'])
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
	if router_left != gateway:
		return "Fel gateway"
	if router_right != gateway2:
		return "Fel gateway"
	if ip & 0xff == 0 or ip & 0xff == 0xff:
		return "IP-addresser får inte sluta på 0 eller 255"
	if ip2 & 0xff == 0 or ip2 & 0xff == 0xff:
		return "IP-addresser får inte sluta på 0 eller 255"
	if (ip>>24) & 0xff == 0 or (ip>>24) & 0xff == 0xff:
		return "IP-addresser får inte börja på 0 eller 255"
	if (ip2>>24) & 0xff == 0 or (ip2>>24) & 0xff == 0xff:
		return "IP-addresser får inte börja på 0 eller 255"
	if (ip & netid) != netid:
		return "Fel Nät-ID"
	if (ip2 & netid2) != netid2:
		return "Fel Nät-ID"
	if (gateway & netid) != netid:
		return "Gateway måste ligga på det lokala nätverket"
	if (gateway2 & netid2) != netid2:
		return "Gateway måste ligga på det lokala nätverket"
	#try:
		#ipaddress.IPv4Network((ip & netmask, netmask))
		#ipaddress.IPv4Network((ip2 & netmask2, netmask2))
	#except:
		#return "Något är fel med nätmask eller ip-addressen"
	return True
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
	if (ip>>24) & 0xff == 0 or (ip>>24) & 0xff == 0xff:
		return "IP-addresser får inte börja på 0 eller 255"
	if (ip2>>24) & 0xff == 0 or (ip2>>24) & 0xff == 0xff:
		return "IP-addresser får inte börja på 0 eller 255"
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
	#try:
		#ipaddress.IPv4Network((ip & netmask, netmask))
		#ipaddress.IPv4Network((ip2 & netmask2, netmask2))
	#except:
		#return "Något är fel med nätmask eller ip-addressen"
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
	return render(request, "exercise/question.html", merge_two_dicts(dict(zip(keys, values)),{'streak': request.session['streak'], 'level': request.session['level']}))


def stage2(request):
	if not 'level' in request.session or not 'streak' in request.session or request.session['level'] < 9:
		pass
	#	return HttpResponse("försök inte")
	if not 'level2' in request.session:
		request.session['level2'] = 0
	if not 'streak' in request.session:
		request.session['streak'] = 0
	level = levels2[request.session['level2']]
	router_left = random.randrange(2**32)
	router_right = random.randrange(2**32)
	netmask = generate_netmask(level['variable_netmask'], level['subnetting'])
	netmask2 = generate_netmask(level['variable_netmask'], level['subnetting'])
	ip = (router_left & netmask) | (~netmask & random.randrange(2**32))
	ip2 = (router_right & netmask2) | (~netmask2 & random.randrange(2**32))
	gateway = router_left
	gateway2 = router_right
	netid = (router_left & netmask)
	netid2 = (router_right & netmask2)
	keys = ['ip', 'netmask', 'gateway', 'ip2', 'netmask2', 'gateway2', 'netid', 'netid2', 'router_left', 'router_right']
	values = []
	allkeys = list(keys)
	allvalues = []
	for x in allkeys:
		allvalues.append(ipstr(locals()[x]))
	for i in range(level['unknowns']):
		del keys[random.randrange(len(keys))]
	for x in keys:
		values.append(ipstr(locals()[x]))
	
	if not check_two_networks(dict(zip(allkeys, allvalues))) == True:
		logger.error(check_two_networks(dict(zip(allkeys, allvalues))))
		return stage2(request)
	return render(request, "exercise/question2.html", merge_two_dicts(dict(zip(keys, values)),{'streak': request.session['streak'], 'level2': request.session['level2']}))


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
	#return JsonResponse({'response':works})
	return HttpResponse(json.dumps({'response': works}), content_type='application/json')
def leader(request):
        ret = ""
        scores = []
        for s in Session.objects.filter():
                s = s.get_decoded()
                score = 0
                score = 1000*s.get('level',0)
                score += 2000*s.get('level2',0)
                score += 100*s.get('streak',0)
                name = s.get('name','Anonymous Coward')
                scores.append((name,score))
        scores = sorted(scores,key=lambda x: x[1],reverse=True)
      
        for s in scores:
                ret += s[0] + ": "+str(s[1]) + "<br/>"
        return render(request, "exercise/leader.html", {'scores': scores[:20]})
def set_name(request):
        if 'name' in request.GET:
                request.session['name'] = request.GET['name']
                return HttpResponseRedirect(request.META.get('HTTP_REFERER'))
        else:
                return HttpResponse("Du gör fel")
def validate2(request):
	works = ""
	try:
		works = check_two_networks(request.POST)
	except IndexError:
		works = "Du har skrivit fel någonstans"
	except ValueError:
		works = "Du har skrivit fel någonstans"
	if works == True:
		request.session['streak'] += 1
		if request.session['streak'] > 0 and request.session['streak'] % 3 == 0:
			request.session['level2'] += 1
	else:
		request.session['streak'] = 0
	return HttpResponse(json.dumps({'response': works}), content_type='application/json')
