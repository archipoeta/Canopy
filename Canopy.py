#!/usr/bin/python
#
# Title: Canopy
# Author: Chris Hart
# Date: 2010.07.10
# Desc: Protection for trees
#		and monkeys.
#

######################
#
# Leaf Config Regexes:
#	If you change these, every leaf conf must match
#	what you put here

leaflog = 'LeafLog'
failcnt = 'FailCount'
failrgxp = 'FailRegex'

######################

import os
import re
import sys
import time
import MySQLdb
import shlex
import string
import subprocess

class Canopy():
	"""A Monkey knowing // How the canopy protects: // Swings on the branches"""
	global basedir
	global conf
	global leaves
	global locales
	global fwhost
	global fwlog
	global black
	global white
	global rbl
	global iptablesbin
	basedir = os.getcwd()
	conf = basedir + "/canopy.conf"

	def loadConfig(self, conf):
		"""Load the canopy config file into the dict Config"""
		f = open(conf, 'r')
		Config = {}
		for line in f:
			if '#' in line or line.startswith("\n"):
				continue
			k,v = line.split("=")
			v = re.sub("'|\"", '', v)
			Config[k] = v.rstrip()
		f.close()
		return Config

	Config 		= loadConfig(object, conf)
	black 		= Config['FW_Blacklist']
	fwhost 		= Config['FW_Host']
	fwlog 		= Config['FW_Log']
	iptablesbin = Config['IptablesBin']
	locales 	= Config['FW_Locales']
	leaves		= Config['FW_Leaves']
	rbl 		= Config['FW_RBL']
	white 		= Config['FW_Whitelist']

	def touchLock(self, b):
		"""Touch or Test the daemon's lockfile"""
		res = ''
		if b:
			os.system("touch %s/.canopy.lock" % (basedir))
			res = int(time.time())
			return res
		else:
			res = os.stat('%s/.canopy.lock' % (basedir))[7]
			return res

	def heartBeat(self, b):
		"""Touch or Test the daemon's lockfile"""
		res = ''
		if b:
			os.system("touch %s/.heartbeat" % (basedir))
			res = int(time.time())
			return res
		else:
			res = os.stat('%s/.heartbeat' % (basedir))[7]
			return res

	def writeLog(self, ip, grav, msg):
		"""Write an entry to the canopy log"""
		t = time.strftime("%Y.%m.%d %H:%M:%S", time.localtime())
		f = open(fwlog, 'a+')
		line = """[%s]\t%s\t%s\t%s\n""" % (t, ip, grav, msg)
		f.write(line)
		f.close

	def ssh2_exec(self, host, args):
		"""Wrapper for os.popen and subprocess.Popen in the future"""
		xargs = "ssh -o stricthostkeychecking=no %s \"%s\"" % (host, args)
		#subprocess sucks
		#xargs = shlex.split(xargs)
		err = os.popen(xargs).read()
		#out = err.stdout
		#(out, err) = (p.stdout, p.stdin)
		if err:
			return err

	def chkBlock(self, ip):
		"""Check if ip is blocked on fwhost"""
		a,b,c,d = ip.split(".")
		t = "%s-save > /root/canopy/.canopy.tmp" % (iptablesbin)
		o = "cat /root/canopy/.canopy.tmp"
		self.ssh2_exec(fwhost, t)
		rules = self.ssh2_exec(fwhost, o)
		if re.search("%s\.%s\.%s\.0[/\d{1,2}].+DROP" % (a,b,c), rules) or re.search("%s\.%s\.%s\.%s[/\d{1,2}].+DROP" % (a,b,c,d), rules):
			print "[%s] is blocked on %s" % (ip, fwhost)
			return 1
		elif re.search("%s\.%s\.%s\.0[/\d{1,2}].+ACCEPT" % (a,b,c), rules) or re.search("%s\.%s\.%s\.%s[/\d{1,2}].+ACCEPT" % (a,b,c,d), rules):
			print "[%s] is actually WHITELISTED on %s believe it or not..." % (ip, fwhost)
			return 2
		else:
			print "[%s] is NOT blocked on %s." % (ip, fwhost)
			return 0

	def accept(self, ip):
		"""Permanently whitelist ip"""
		b = self.chkBlock(ip)
		if b == 2:
			sys.exit()
		if '/' in ip:
			pass
		else:
			ip += '/32'
		cmd = "%s -D INPUT -s %s -j DROP ; %s -I INPUT -s %s -j ACCEPT" % (iptablesbin, ip, iptablesbin, ip)
		os.system("echo %s >> %s" % (ip, white))
		print "[%s] has been whitelisted on %s" % (ip, fwhost)
		self.ssh2_exec(fwhost, cmd)
		self.writeLog("NET", "ACCEPT", "%s : Whitelisted on %s" % (ip, fwhost))

	def chkNet(self, ip):
		"""Query hostip db for subnet locale"""
		a,b,c,d = ip.split(".")
		db = MySQLdb.connect(host="localhost", user="chkNet", passwd="h0st1p!", db="hostip")
		cursor = db.cursor()
		cursor.execute("select name,code from countries where id = (select country from ip4_%s where b = %s and c = %s)" % (a, b, c))
		result = cursor.fetchall()
		if not result:
			result = [['Nowhere','UNK'],]
		name = string.capwords(result[0][0])
		code = result[0][1]
		self.writeLog("NET", "CHECK", "%s : NetLocale => %s" % (ip, code))
		print "[%s] hails from sunny %s" % (ip, name)
		return code

	def drop(self, ip):
		"""Permanently blacklist ip"""
		b = self.chkBlock(ip)
		if b == 1:
			sys.exit()
		if '/' in ip:
			pass
		else:
			ip += '/32'
		cmd = "%s -I INPUT -s %s -j DROP" % (iptablesbin, ip)
		os.system("echo %s >> %s" % (ip, black))
		print "[%s] has been blocked on %s" % (ip, fwhost)
		self.ssh2_exec(fwhost, cmd)
		self.writeLog("NET", "DROP", "%s : Blocked on %s" % (ip, fwhost))

	def flush(self):
		"""Flush the firewall on fwhost, and reload canopy.rbl"""
		cmd = "%s -F" % (iptablesbin)
		cme = "%s-restore < %s" % (iptablesbin, rbl)
		whites = []
		blacks = []

		w = open(white, 'r')

		for line in w:
			whites.append(line)
		w.close()

		b = open(black, 'r')

		for line in b:
			blacks.append(line)
		b.close()

		self.ssh2_exec(fwhost, cmd)
		self.ssh2_exec(fwhost, cme)

		for ip in whites:
			cmw = "%s -I INPUT -s %s -j ACCEPT" % (iptablesbin, ip.rstrip())
			self.ssh2_exec(fwhost, cmw)

		for ip in blacks:
			cmb = "%s -I INPUT -s %s -j DROP" % (iptablesbin, ip.rstrip())
			self.ssh2_exec(fwhost, cmb)

		print "%s firewall flushed.. [OK]" % (fwhost)
		self.writeLog(fwhost, "FLUSH", "Rules flushed, and default ruleset loaded")

	def help(self):
		"""The help menu"""
		print """
Usage: ./canopy [OPTIONS] [IPADDR]

	:OPTIONS:
	-a  | --accept		ACCEPT packets from IPADDR
	-cn | --checkn		Check where IPADDR is from (country code)
	-cb | --checkb		Check whether we have a BLOCK in place for IPPADDR
	-d  | --drop		DROP packets from IPADDR
	-f  | --flush		FLUSH firewall, and reload DEFAULT ruleset.

	-h | --help			This help menu

Usage: ./canopy

Scans logs for failed logins and ./canopy -d IPADDR based on #failures
assigned in canopy.conf, and an internal weight.
More modularity to come.\n"""

	def reverseList(self,list):
		"""Custom reverse list() method"""
		tsil = []
		i = len(list)
		while i > 0:
			i = i - 1
			tsil.append(list[i])
		return tsil

	def reverseDict(self,dict):
		"""Custom reverse dict() method"""
		tcid = {}
		keys = dict.values()
		vals = dict.keys()
		for v in vals:
			k = dict[v]
			if k in tcid.keys():
				tcid[k].append(v)
			else:
				tcid[k] = [v]
		return tcid

	def stop(self):
		"""Trapped stop daemon method, so we can write to the log... annnnd kill all the CHLDren"""
		self.writeLog("Local", "STOP", "Daemon stopped @ %s" % int(time.time()))
		os.system("killall -9 canopy")

	def GoBananas(self, pid, conf):
		"""Canopy Daemon method: expects to be called by a fork()ed child of canopy.. loads and processes leaf configs, and monitors leaf logs accordingly"""
		start = self.touchLock(0)
		beat = self.heartBeat(1)
		leaf = os.path.basename(conf)
		leaf = leaf.rstrip("\.conf")
		weight = {}
		oline = ''
		Config = self.loadConfig(conf)
		log = Config[leaflog]
		fail = Config[failrgxp]
		fcnt = int(Config[failcnt])
		self.writeLog("Local", "LOAD", "Leaf for Canopy.%s (%s) started @ %s" % (leaf, pid, int(time.time())))

		while 1:
			cur = int(time.time())
			f = open(log,'r')
			lines = f.readlines()
			line = lines[-1]
			f.close
			if line == oline:
				#self.writeLog("Local", "DEBUG", "line = oline : No movement, sleeping 1 second")
				time.sleep(1)
				continue
			if not re.search(fail, line):
				#self.writeLog("Local", "DEBUG", "no re.search(fail, line) : No movement, sleeping 3 seconds")
				time.sleep(1)
			else:
				m = re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
				ip = m.group(0)
				ip = ip.rstrip()

				if not ip in weight.keys():
					weight[ip] = 1
				else:
					val = weight[ip]
					val = val + 1
					weight[ip] = int(val)
				self.writeLog(fwhost, "HIT", "%s has matched the failregex for %s: {%s}" % (ip, leaf, weight[ip]))

			oline = line

			if not weight.keys():
				if cur - beat >= 3600:
					beat = self.heartBeat(1)
					self.writeLog("Local", "BEAT", "Heartbeat @ %s" % int(time.time()))
				if cur - start >= 86400:
					start = self.touchLock(1)
					weight = {}
				#self.writeLog("Local", "DEBUG", "not weight : No movement, sleeping 5 second")
				time.sleep(2)
				continue

			gravity = self.reverseDict(weight)
			for k in gravity:
				if k < fcnt:
					continue
				for ip in gravity[k]:
					s = self.chkBlock(ip)
					if s > 0:
						continue
					a,b,c,d = ip.split(".")
					net = self.chkNet(ip)
					if not re.search(locales, net):
						blocks = [ a, b, c, '0/24' ]
						ip = ".".join(blocks)
					else:
						blocks = [ a, b, c, d+'/32' ]
						ip = ".".join(blocks)
					xargs = "cd %s && ./canopy -d %s" % (basedir, ip)
					err = os.popen(xargs).read()
					if err:
						print err
						self.writeLog("****", "ERROR", "Error blocking %s on %s : %s" % (ip, fwhost, err))
					self.writeLog("NET", "DROP", "%s : Blocked on %s => {%s}" % (ip, fwhost, k))
