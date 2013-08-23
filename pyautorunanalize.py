#! /bin/env python

"""
	PyAutorunalizer 0.1
	Python script for autorunalize: http://sysinternals.com/autoruns.com listing autoruns Windows 
	items. Version 11.6 or greater needed.
	http://Virutotal.com externa database of viruses.
	original idea: http://trustedsignal.blogspot.com.es/2012/02/finding-evil-automating-autoruns.html
	original implementation uses cygwin32, bash and other blobs.
	Virustotal API refer: https://github.com/botherder/virustotal/
	Autoruns is part of Sysinternals' suit and owns the copyright. Windows are trademark of Microsoft.
	Licence: GPLv2

	#Use this script at your own. No warraties nor 
	This script is not inteded as a substitute for any antivirus. Is just a sanity check.
	Individuals htat noncomplain the Virustotal or sysinternals terms or harms the antivirus
	industry, are out of my resposability.
"""

import xml.etree.ElementTree as ElementTree
import json
import urllib,urllib.request
import sys,os,getopt,subprocess

fnull = open(os.devnull, "w")

def runanalizer(API_KEY):
	#Check for autorunsc.exe
	try:
	   with open('./autorunsc.exe'): pass
	except IOError:
	   print('autorunsc.exe binary not found! Download from https://live.sysinternals.com/autorunsc.exe')
	   sys.exit(3)
	try:   
		if os.environ['HTTP_PROXY'] != None:
			proxies = {'https': 'http://{0}'.format(os.environ['HTTP_PROXY'])}
			urllib.request.ProxyHandler(proxies)
			print("[Info] Going through proxies: ",proxies)
	except KeyError:
		#not defined
		pass
		
	print('[Info] Getting list of files to analise from Autoruns ...')
	autoruns_proc = subprocess.Popen(['autorunsc.exe', "/accepteula", '-xaf'], stdout=subprocess.PIPE, stderr = fnull)
	autoruns_xml = (autoruns_proc.communicate()[0].decode("utf_16"))
	autoruns_xml.replace('\r\n','\n')
	
	#parse XML output
	#items =[[]]
	try:
		autoruns_tree = ElementTree.fromstring(autoruns_xml)
	except xml.etree.ElementTree.ParseError as e:
		print('[Error] Error parsing xml autoruns\' output. \n	Is Autoruns\' latest version?\n', e)
		sys.exit(1002)
	for item in autoruns_tree:
		text = "[Object]"
		if item is None:
			text = text + " Invalid item (mostly not a binary image)\n"
			break
		imagepath = item.findtext('imagepath')
		name = item.findtext('itemname')
		if imagepath is not None:
			sha256hash = item.findtext('sha256hash')
			text = text + '' + name + '\n	' + imagepath + '\n	' + sha256hash + '\n 	 scanning... '
			print(text)
			result = scan(sha256hash, API_KEY)
			print(result)


def scan(sha256hash, API_KEY):
        VIRUSTOTAL_REPORT_URL = 'https://www.virustotal.com/vtapi/v2/file/report'
        VIRUSTOTAL_SCAN_URL = 'https://www.virustotal.com/vtapi/v2/file/scan'
        
        if sha256hash == None:
            response = "No valid hash for this file"
            return response
        
        data = urllib.parse.urlencode({
            'resource' : sha256hash,
            'apikey' : API_KEY
            })
        data = data.encode('utf-8')
        try:
            request = urllib.request.Request(VIRUSTOTAL_REPORT_URL, data)
            reply = urllib.request.urlopen(request)
            answer = 42
            answer = reply.read().decode("utf-8")
            report = json.loads(answer)
        except Exception as e:
            error = "\n[Error] Cannot obtain results from VirusTotal: {0}\n".format(e)
            return error
            sys.exit(4)

        int(report['response_code']) == 0
        if int(report['response_code']) == 0:
            response = (report['verbose_msg'])
        elif int(report['response_code']) < 0:
            response = 'Not found on Virustotal database!'
			#Shall send the file if is not on virustotal. 
        else:
            response = 'FOUND'
            if int(report['positives']) >= 0:
                response = response + 'but not infected.'
            else:
                for av, scan in report['scans'].items():
                    if scan == 'detected':
                        response = response + ' INFECTED!\n	 engine:' + av + ',\n	 malware:' + scan['result'] + '\n'

        return response

def help():
	print(main.__doc__)
	sys.exit(0)


def main(argv):
   """\n
   Script for Windows basic security check using Sysinternal\'s Autoruns
   and Virustotal.com\n
   Thereforce, you need to get a public API Key from http://www.virustotal.com for your 
   scripting analysis\n
   and autorunsc.exe binary.\n
   	Usage:\n
   	   autorunalize.exe [--help] --API-KEY YOUR_API_KEY\n
   	   -h, --help		Shows this help.\n
   	   -a, --API-KEY		Your public API key from Virustotal.
   						This a 64 characters hexadecimal string.\n
   	Example:\n
   	   ./autorunalize.exe --API-KEY YOUR_API_KEY\n
   """

   API_KEY = ''
   try:
       opts, args = getopt.getopt(argv,"ha:",["help","API-KEY="])
   except getopt.GetoptError:
      print('pyrunanalizer.py --API-KEY YOUR_API_KEY_HERE')
      sys.exit(2)
   for opt, arg in opts:
      if opt in ('-h','--help'):
         help()
         sys.exit()
      elif opt in ("-a", "--API-KEY"):
         API_KEY = arg
         runanalizer(API_KEY)
      else:
	      help()

if __name__ == "__main__":
   main(sys.argv[1:])
