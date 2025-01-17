#!/usr/bin/env python 
# -*- coding:utf-8 -*- 
# WPSeku - Wordpress Security Scanner 
# Coded by Momo Outaadi (@M4ll0k) (C) 2017

import urllib
from . import wp_print
import sys
from . import wp_checker

class WPRequest:
	"""Connection Class"""
	bp = wp_print.WPPrint()
	###########################
	def __init__(self,**kwargs):
		self.agent = None if 'agent' not in kwargs else kwargs['agent']
		self.proxy = None if 'proxy' not in kwargs else kwargs['proxy']
		self.redir = True if 'redir' not in kwargs else kwargs['redir']

	def Send(self,url,method='GET',payload=None,headers=None,cookie=None):
		if method not in ['GET','POST']:
			sys.exit(self.bp.bprint('Invalid {} method, try with \'GET\' or \'POST\''.format(method)))
		if payload is None: payload = {}
		if headers is None: headers = {}
		# add user_agent 
		headers['User-agent'] = self.agent
		handlers = [urllib.request.HTTPHandler(),urllib.request.HTTPSHandler()]
		# Set cookies
		if cookie != None:
			handlers.append(urllib.request.HTTPCookieProcessor(cookie))
		# Set redirect
		if self.redir == False:
			""
			#handlers.append(NoRedirectHandler())
		# Set proxy
		if self.proxy:
			proxies = {'http':self.proxy,'https':self.proxy}
			handlers.append(urllib.parse.ProxyHandler(proxies))
		# Set opener
		opener = urllib.request.build_opener(*handlers)
		urllib.request.install_opener(opener)
		# Method GET
		if method == "GET":
			if payload: url = "{}".format(Check().check(url,payload))
			req = urllib.request.Request(url,headers=headers)
		# Method POST
		if method == "POST":
			req = urllib.request.Request(url,data=payload,headers=headers)

		# Response
		try:
			resp = urllib.request.urlopen(req)
		except urllib.error.HTTPError():
			resp = ""
		return resp.read().decode('utf-8'),resp.geturl(),resp.getcode(),resp.info()

# class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
# 	def http_error_302(self,req,fp,code,msg,headers):
# 		pass 
# 	http_error_302 = http_error_302 = http_error_302 = http_error_302

class Check:
	def check(self,url,path):
		return url+'?'+path