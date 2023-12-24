#!/usr/bin/env python 
# -*- coding:utf-8 -*- 
# WPSeku - Wordpress Security Scanner 
# Coded by Momo Outaadi (@M4ll0k) (C) 2017

from core.lib import wp_checker
from core.lib import wp_colors
from core.lib import wp_print
from core.lib import wp_request
import re
import requests 
import json 

class WPGeneric:
	"""WordPress Generic Checks"""
	check_ = wp_checker.WPChecker()
	print_ = wp_print.WPPrint()
	def __init__(self,agent,proxy,redirect,url):
		self.url = url
		# request 
		self.req = wp_request.WPRequest(agent=agent,proxy=proxy,redir=redirect)

	def xmlrpc(self):
		# Check xmlrpc.php 
		try:
			url = self.check_.check(self.url,"/xmlrpc.php")
			# return html,url,code and info 
			html,uri,code,info = self.req.Send(url) 
			if html and code == 405:
				self.print_.aprint("XML-RPC Interface available under: {}".format(uri))
		except Exception:
			pass 

	def robots(self):
		# Check robots.txt
		try:
			url = self.check_.check(self.url,"robots.txt")
			# return html,url,code and info
			html,uri,code,info = self.req.Send(url)
			if html and code == 200:
				self.print_.aprint("Robots available under: {}".format(uri))
				print("\r\n%s\n"%(html))
		except Exception:
			pass

	def sitemap(self):
		# Check sitemap.xml
		try:
			url = self.check_.check(self.url,"sitemap.xml")
			# return html,url,code and info
			html,uri,code,info = self.req.Send(url)
			if html and code == 200:
				self.print_.aprint("Sitemap available under: {}".format(uri))
		except Exception:
			pass

	def readme(self):
		# Check readme.html file
		try:
			url = self.check_.check(self.url,"readme.html")
			# return html,url,code and info
			html,uri,code,info = self.req.Send(url)
			if html and code == 200:
				self.print_.aprint("Readme available under: {}".format(uri))
		except Exception:
			pass 

	def fullpathdisc(self):
		# Check full path disclosure 
		try:
			url = self.check_.check(self.url,"wp-includes/rss-functions.php")
			# return html,url,code and info
			html,uri,code,info = self.req.Send(url)
			if html and code == 200:
				if re.search('Fatal error',html):
					self.print_.bprint("Full Path Disclosure: {}".format(uri))
		except Exception:
			pass

	def version(self):
		# Check wordpress version
		try:
			# check wordpress version via wp-links-opml.php
			# check url + path
			url = self.check_.check(self.url,"wp-links-opml.php")
			# return html,url,code and info
			html,uri,code,info = self.req.Send(url)
			# find wordpress version with this regex (\S+WordPress/(\d+.\d+[.\d+]*))
			vers = re.findall('\S+WordPress/(\d+.\d+[.\d+]*)',html) 
			if vers != []:
				self.print_.aprint("Running WordPress version: %s"%(vers[0]))
				# Check wordpress version vulns
				self.wpvulns(vers)
		except Exception:
			try:
				# check wordpress version via feed
				url = self.check_.check(self.url,"feed")
				# return html,url,code and info
				html,uri,code,info = self.req.Send(url)
				# find wordpress version with this regex (\S+?v=(\d+.\d+[.\d+]*))
				vers = re.findall('\S+?v=(\d+.\d+[.\d+]*)',html)
				if vers != []:
					self.print_.aprint("Running WordPress version: %s"%(vers[0]))
					# Check wordpress version vulns
					self.wpvulns(vers)
			except Exception:
				try:
					# check wordpress version via feed/atom
					url = self.check_.check(self.url,"/feed/atom")
					# return html,url,code and info
					html,uri,code,info = self.req.Send(url)
					# find wordpress version with this regex (<generator uri="http://wordpress.org/" version="(\d+\.\d+[\.\d+]*)")
					vers = re.findall('<generator uri="http://wordpress.org/" version="(\d+\.\d+[\.\d+]*)"',html)
					if vers != []:
						self.print_.aprint("Running WordPress version: %s"%(vers[0]))
						# Check wordpress version vulns
						self.wpvulns(vers)
				except Exception:
					try:
						# check wordpress version via feed/rdf
						url = self.check_.check(self.url,"feed/rdf")
						# return html,url,code and info
						html,uri,code,info = self.req.Send(url)
						# find wordpress version with this regex (\S+?v=(\d+.\d+[.\d+]*))
						vers = re.findall('\S+?v=(\d+.\d+[.\d+]*)',html)
						if vers != []:
							self.print_.aprint("Running WordPress version: %s"%(vers[0]))
							# Check wordpress version vulns
							self.wpvulns(vers)
					except Exception:
						try:
							# check wordpress version via comments/feed
							url = self.check_.check(self.url,"comments/feed")
							# return html,url,code and info
							html,uri,code,info = self.req.Send(url)
							# find wordpress version with this regex (\S+?v=(\d+.\d+[.\d+]*))
							vers = re.findall('\S+?v=(\d+.\d+[.\d+]*)',html)
							if vers != []:
								self.print_.aprint("Running WordPress version: %s"%(vers[0]))
								# Check wordpress version vulns
								self.wpvulns(vers)
						except Exception:
							try:
								# check wordpress version via readme.html file
								url = self.check_.check(self.url,"readme.html")
								# return html,url,code and info
								html,uri,code,info = self.req.Send(url)
								# find wordpress version with this regex (.*wordpress-logo.png" /></a>\n.*<br />.* (\d+\.\d+[\.\d+]*)\n</h1>)
								vers = re.findall('.*wordpress-logo.png" /></a>\n.*<br />.* (\d+\.\d+[\.\d+]*)\n</h1>',html)
								if vers != []:
									self.print_.aprint("Running WordPress version: %s"%(vers[0]))
									# Check wordpress version vulns
									self.wpvulns(vers)
							except Exception:
								try:
									# check wordpress version via meta generator
									url = self.check_.check(self.url,"")
									# return html,url,code and info
									html,uri,code,info = self.req.Send(url)
									# find wordpress version with this regex (<meta name="generator" content="WordPress (\d+\.\d+[\.\d+]*)")
									vers = re.findall('<meta name="generator" content="WordPress (\d+\.\d+[\.\d+]*)"',html)
									if vers != []:
										self.print_.aprint("Running WordPress version: %s"%(vers[0]))
										# Check wordpress version vulns
										self.wpvulns(vers)
								except Exception:
									self.print_.aprint("Not found run WordPress version")

	def headers(self):
		# Check interesting headers
		self.print_.aprint("Interesting headers: ")
		# check url 
		url = self.check_.check(self.url,"")
		# return html,url,code and info
		html,uri,code,info = self.req.Send(url)
		print("")
		print(info.get_all('content-encoding'))
		if info.get_all('content-encoding'):
			print("Content-Encoding: {}".format(info.get_all('content-encoding')))
		if info.get_all('content-length'):
			print("Content-Length: {}".format(info.get_all('content-length')))
		if info.get_all('connection'):
			print("Connection: {}".format(info.get_all('connection')))
		if info.get_all('content-type'):
			print("Content-Type: {}".format(info.get_all('content-type')))
		if info.get_all('cache-control'):
			print("Cache-Control: {}".format(info.get_all('cache-control')))
		if info.get_all('server'):
			print("Server: {}".format(info.get_all('server')))
		if info.get_all('keep-alive'):
			print("Keep-Alive: {}".format(info.get_all('keep-alive')))
		if info.get_all('link'):
			print("Link: {}".format(info.get_all('link')))
		if info.get_all('x-pingback'):
			print("X-Pingback: {}".format(info.get_all('x-pingback')))
		if info.get_all('cf-ray'):
			print("CF-RAY: {}".format(info.get_all('cf-ray')))
		if info.get_all('cookie'):
			print("Cookie: {}".format(info.get_all('cookie')))
		if info.get_all('x-mod-pagespeed'):
			print("X-Mod-Pagespeed: {}".format(info.get_all('x-mod-pagespeed')))
		if info.get_all('x-powered-by'):
			print("X-Powered-By: {}".format(info.get_all('x-powered-by')))
		if info.get_all('x-xss-protection'):
			print( "X-Xss-Protection: {}".format(info.get_all('x-xss-protection')))
		print ("")

	def wpconfig(self):
		# Check wp-config.php 
		try:
			url = self.check_.check(self.url,"wp-config.php")
			# return html,url,code and info
			html,uri,code,info = self.req.Send(url)
			if html and code == 200:
				self.print_.aprint("wp-config available under: %s"%(uri))
		except Exception:
			pass

	def wpconfigbackup(self):
		# Check wp-config backup 
		db = open("core/db/wpconfig.txt","rb")
		for x in db:
			try:
				url = self.check_.check(self.url,str(x))
				# return html,url,code and info
				html,uri,code,info = self.req.Send(url)
				if html and code == 200:
					self.print_.bprint("wp-config backup available under: %s"%(uri))
			except Exception:
				pass 

	def wpconfigsm(self):
		# Check wp-config-sample.php 
		try:
			url = self.check_.check(self.url,"wp-config-sample.php")
			# return html,url,code and info
			html,uri,code,info = self.req.Send(url)
			if html and code == 500:
				self.print_.bprint("wp-config-sample available under: %s"%(uri))
		except Exception:
			pass

	def dirlisting(self):
		# Check dir listing enabled
		file = ["/wp-admin","/wp-content","/wp-includes/","/wp-content/themes/","/wp-content/plugins/"]
		for x in file:
			try:
				url = self.check_.check(self.url,str(x))
				# return html,url,code and info
				html,uri,code,info = self.req.Send(url)
				if re.search("Index of",html) and code == 200:
					self.print_.bprint("Dir {} listing enabled under: {}".format(x,uri))
			except Exception:
				pass

	def license(self):
		# Check wordpress license
		file = ["license.txt","licensa.txt"]
		for x in file:
			try:
				url = self.check_.check(self.url,str(x))
				# return html,url,code and info
				html,uri,code,info = self.req.Send(url)
				if html and code == 200:
					self.print_.aprint("License available under: %s"%(uri))
			except Exception:
				pass

	def pingback(self):
		# Check pingback vulnerability
		payload = """<?xml version="1.0" encoding="utf-8"?> 
		<methodCall><methodName>pingback.ping</methodName><params>
		<param><value><string>http://site.com:22</string></value></param>
		<param><value><string>"""+self.url+"""<param><value><string></params></methodCall>"""
		try:
			url = self.check_.check(self.url,"xmlrpc.php")
			# return html,url,code and info
			html,uri,code,info = self.req.Send(url,method="POST",payload=payload)
			if re.search("<name>16</name>",html) and code==200:
				self.print_.bprint("Website vulnerable to XML-RPC Pingback Force Vulneravility")
		except Exception:
			pass

	def wpvulns(self,ver):
		# Check wordpress version vulns 
		try:
			v1,v2,v3 = [x.split('.') for x in ver][0]
			self.vers = (v1+v2+v3)
		except ValueError:
			try:
				v1,v2 = [x.split('.') for x in ver][0]
				self.vers = (v1+v2)
			except ValueError:
				self.vers = ver[0]
		try:
			# disable requests warnings
			req =requests.packages.urllib3.disable_warnings()
			# https://wpvulndb.com/api/v2/wordpresses/444 <-- wordpress version 4.4.4
			req =requests.get("https://wpvulndb.com/api/v2/wordpresses/"+str(self.vers),verify=False)
			jso =json.loads(req.content)
			if jso[str(ver[0])]["vulnerabilities"]:
				for x in range(len(jso[str(ver[0])]["vulnerabilities"])):
					self.print_.eprint("Title: %s"%(jso[str(ver[0])]["vulnerabilities"][x]["title"]))
					if jso[str(ver[0])]["vulnerabilities"][x]["references"]:
						for z in range(len(jso[str(ver[0])]["vulnerabilities"][x]["references"]["url"])):
							self.print_.dprint("Reference: %s"%(jso[str(ver[0])]["vulnerabilities"][x]["references"]["url"][z]))
					self.print_.dprint("Fixed in: %s"%(jso[str(ver[0])]["vulnerabilities"][x]["fixed_in"]))
					print("")
			else:
				self.print_.eprint("Not found vulnerabilities")
				print 
		except Exception:
			print 

	def init(self):
		self.sitemap()
		self.readme()
		self.robots()
		self.xmlrpc()
		self.license()
		self.wpconfig()
		self.wpconfigsm()
		self.wpconfigbackup()
		self.dirlisting()
		self.pingback()
		self.fullpathdisc()
		self.headers()
		self.version()
		