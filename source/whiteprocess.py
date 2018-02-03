#         whiteprocess (PyELF beta 0.8) : Whitelist Threads Filter for UNIX
#
#                  Copyright (C) 2017, 2018 Stefano Gorresio
#
#    This file is part of whiteprocess.
#
#    whiteprocess is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    whiteprocess is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import os
import psutil
import time
import hashlib
import getpass
import threading
from SocketServer import ThreadingMixIn 
from whiteprocess_common import *
from whiteprocess_agent import *
from whiteprocess_socket import *


# Class for manage lists
class whiteprocess_list():
	
	main_list = None
	
	def __init__(self, lista = None):
		self.main_list = []
		if not lista == None:
			self.main_list += [element for element in lista]
	
	def add(self, element):
		self.main_list.append(element)
	
	def add_list(self, lista):
		self.main_list += [element for element in lista]


# Class for manage configurations
class whiteprocess_configurations():
	
	# Variables
	CONF_FILE = "/etc/whiteprocess.conf"
	LOG_FILE = ""
	WP_DIRECTORY = "/usr/share/whiteprocess/"
	STATUS_FILE = WP_DIRECTORY+"whiteprocess.status"
	TIME_CHECK = 0
	EXE_FILTER = False
	ARGS_FILTER = False
	AFTER_EXEC_FILTER = False
	REMOTE_CHECK = False
	USE_PASSWORD = False
	PASSWORD = ""
	TCP_PORT = 0
	EXE_ALLOW = None
	PATH_ALLOW = None
	ARGS_ALLOW = None
	AFTER_EXEC_KILL = None
	
	def __init__(self):   # Read from configuration file
		try:
			fp = open(self.CONF_FILE, "r")
			dati = fp.read()
			fp.close()
		except:
			print_error("Error in I/O "+self.CONF_FILE)
		dati = dati.replace(" ", "")
		dati = dati.replace("\t", "")
		row = dati.split("\n")
		self.EXE_ALLOW = whiteprocess_list()
		self.PATH_ALLOW = whiteprocess_list()
		self.ARGS_ALLOW = whiteprocess_list()
		self.AFTER_EXEC_KILL = whiteprocess_list()
		for i in range(len(row)):
			pez = row[i].split("=")
			if pez[0] == "TIME_CHECK":
				self.TIME_CHECK = float(pez[1])
			elif pez[0] == "LOG_FILE":
				self.LOG_FILE = pez[1]
			elif pez[0] == "EXE_FILTER":
				if pez[1] == "yes":
					self.EXE_FILTER = True
				elif pez[1] == "no":
					self.EXE_FILTER = False
				else:
					print_error(self.CONF_FILE+" malformed: row:"+str(i)+" \""+row[i]+"\"")
			elif pez[0] == "ARGS_FILTER":
				if pez[1] == "yes":
					self.ARGS_FILTER = True
				elif pez[1] == "no":
					self.ARGS_FILTER = False
				else:
					print_error(self.CONF_FILE+" malformed: row:"+str(i)+" \""+row[i]+"\"")
			elif pez[0] == "AFTER_EXEC_FILTER":
				if pez[1] == "yes":
					self.AFTER_EXEC_FILTER = True
				elif pez[1] == "no":
					self.AFTER_EXEC_FILTER = False
				else:
					print_error(self.CONF_FILE+" malformed: row:"+str(i)+" \""+row[i]+"\"")
			elif pez[0] == "USE_PASSWORD":
				if pez[1] == "yes":
					self.USE_PASSWORD = True
				elif pez[1] == "no":
					self.USE_PASSWORD = False
				else:
					print_error(self.CONF_FILE+" malformed: row:"+str(i)+" \""+row[i]+"\"")
			elif pez[0] == "REMOTE_CHECK":
				if pez[1] == "yes":
					self.REMOTE_CHECK = True
				elif pez[1] == "no":
					self.REMOTE_CHECK = False
				else:
					print_error(self.CONF_FILE+" malformed: row:"+str(i)+" \""+row[i]+"\"")
			if self.USE_PASSWORD:
				if pez[0] == "PASSWORD":
					self.PASSWORD = pez[1]
			if self.REMOTE_CHECK:
				if pez[0] == "TCP_PORT":
					self.TCP_PORT = int(pez[1])
			if self.EXE_FILTER:
				if row[i] == "EXE_ALLOW{":
					j = i + 1
					while row[j] != "}":
						self.EXE_ALLOW.add(row[j])
						j += 1
			if self.EXE_FILTER:
				if row[i] == "PATH_ALLOW{":
					j = i + 1
					while row[j] != "}":
						self.PATH_ALLOW.add(row[j])
						j += 1
			if self.ARGS_FILTER:
				if row[i] == "ARGS_ALLOW{":
					j = i + 1
					while row[j] != "}":
						self.ARGS_ALLOW.add(row[j].split(":"))
						j += 1
			if self.AFTER_EXEC_FILTER:
				if row[i] == "AFTER_EXEC_KILL{":
					j = i + 1
					while row[j] != "}":
						self.AFTER_EXEC_KILL.add(row[j])
						j += 1


# Class for manage status
class whiteprocess_status():
	
	STATUS_FILE = None
	
	def __init__(self, status_file):
		self.STATUS_FILE = status_file
	
	
	def set(self, status):	
		try:
			fp = open(self.STATUS_FILE, "w")
			dati = fp.write(status)
			fp.close()
		except:
			print_error("Error in I/O "+self.STATUS_FILE)


	def get(self):	
		try:
			fp = open(self.STATUS_FILE, "r")
			return fp.read()
		except:
			print_error("Error in I/O "+self.STATUS_FILE)


def check_process():
	exes = []
	pids_list = psutil.pids()
	if pids_list[len(pids_list)-1] == 0:    # Exclude PID 0 (BSD kernel)
		pids_list.pop()
	for i in pids_list:
		p = psutil.Process(i)
		if (p.exe() not in exes) and (p.exe() != ""):
			exes.append(p.exe())
	# Print info
	print("Found "+str(len(exes))+" executables running:")
	for i in exes:
		print(i)
	return exes


def check_commands():
	cmds = []
	pids_list = psutil.pids()
	if pids_list[len(pids_list)-1] == 0:    # Exclude PID 0 (BSD kernel)
		pids_list.pop()
	for i in pids_list:
		p = psutil.Process(i)
		if (" ".join(p.cmdline()) not in cmds) and (p.exe() != ""):
			cmds.append(" ".join(p.cmdline()))
	# Print info
	print("Found "+str(len(cmds))+" commands running:")
	for i in cmds:
		print(i)
	sys.exit()


### AUTOCONF ###

def auto_check_exe(dati):
	exes = check_process()
	stringa = ""
	for i in exes:
		stringa += "\n"+i
	dati = dati.replace("EXE_ALLOW{\n}", "EXE_ALLOW{"+stringa+"\n}")
	return dati


def add_allowed_path(dati, path):
	dati = dati.replace("PATH_ALLOW{\n", "PATH_ALLOW{\n"+path+"\n")
	return dati


def autoconf(CONF_FILE, WP_DIRECTORY):
	print("\n\t** whiteprocess Guided Configuration **")
	
	answer = keyboard_input("\nDo you want reset config file? (yes/no): ")
	if answer == "yes":	
		if os.system("cp "+WP_DIRECTORY+"whiteprocess.conf "+CONF_FILE) == 0:
			print(CONF_FILE+" resetted.")
		else:
			print_error("Problem with reset configuration file.")
	elif answer == "no":
		print("If you do not reset the config file, you will not continue.\nExit.")
		sys.exit()
	else:
		print("Invalid answer. Considered \"no\".")
		print("If you do not reset the config file, you will not continue.\nExit.")
		sys.exit()
	
	try:
		fp = open(CONF_FILE, "r")
		dati = fp.read()
		fp.close()
	except:
		print_error("Error in I/O "+CONF_FILE)
	
	answer = keyboard_input("\nDo you want insert in executables allowed (EXE_FILTER) current executables running? (yes/no): ")
	if answer == "yes":
		dati = auto_check_exe(dati)
	elif answer == "no":
		pass
	else:
		print("Invalid answer. Considered \"no\".")
	
	answer = keyboard_input("\nDo you want insert executables in '/bin/' in whitelist? (yes/no): ")
	if answer == "yes":
		dati = add_allowed_path(dati, "/bin/")
	elif answer == "no":
		pass
	else:
		print("Invalid answer. Considered \"no\".")
	
	answer = keyboard_input("\nDo you want insert executables in '/usr/bin/' in whitelist? (yes/no): ")
	if answer == "yes":
		dati = add_allowed_path(dati, "/usr/bin/")
	elif answer == "no":
		pass
	else:
		print("Invalid answer. Considered \"no\".")
	
	answer = keyboard_input("\nDo you want enable Arguments Filter? (yes/no): ")
	if answer == "yes":
		dati = dati.replace("ARGS_FILTER = no", "ARGS_FILTER = yes")
		print("Arguments Filter enabled... ARGS_ALLOW must be filled manually.")
	elif answer == "no":
		pass
	else:
		print("Invalid answer. Considered \"no\".")
	
	answer = keyboard_input("\nDo you want enable After Exec Filter? (yes/no): ")
	if answer == "yes":
		dati = dati.replace("AFTER_EXEC_FILTER = no", "AFTER_EXEC_FILTER = yes")
		print("After Exec Filter enabled... AFTER_EXEC_KILL must be filled manually.")
	elif answer == "no":
		pass
	else:
		print("Invalid answer. Considered \"no\".")
	
	answer = keyboard_input("\nTime in second from one control to another? (Default: 5): ")
	if not answer == "":
		try:
			float(answer)
			dati = dati.replace("TIME_CHECK = 5", "TIME_CHECK = "+answer)
			print("Time setted to "+answer+" seconds.")
		except:
			print("Invalid input: must be a decimal float.")
			print("Time setted to 5 seconds.")
	else:
		print("Time setted to 5 seconds.")
	
	answer = keyboard_input("\nDo you want enable Password for stopping service? (yes/no): ")
	if answer == "yes":
		dati = dati.replace("USE_PASSWORD = no", "USE_PASSWORD = yes")
		flag = True
		while flag:
			print("Insert password:")
			password = getpass.getpass()
			print("Repeat password:")
			password2 = getpass.getpass()
			if password == password2:
				if password == "":
					print("WARNING: Password void is not safe.")
				dati = dati.replace("PASSWORD = 0", "PASSWORD = "+hash_string(password))
				flag = False
			else:
				print("Password not matched. Retry.\n")
		print("Password saved.")
	elif answer == "no":
		pass
	else:
		print("Invalid answer. Considered \"no\".")
	
	answer = keyboard_input("\nDo you want enable Remote Control? (yes/no): ")
	if answer == "yes":
		dati = dati.replace("REMOTE_CHECK = no", "REMOTE_CHECK = yes")
		answer = keyboard_input("\nInsert TCP port to listening? (Default: 2357): ")
		if not answer == "":
			try:
				int(answer)   # Check if integer
				dati = dati.replace("TCP_PORT = 2357", "TCP_PORT = "+answer)
				print("TCP port setted to "+answer+".")
			except:
				print("Invalid input: must be an integer.")
				print("TCP port setted to 2357.")
		else:
			print("TCP port setted to 2357.")
	elif answer == "no":
		pass
	else:
		print("Invalid answer. Considered \"no\".")
	
	
	print("\nSaving configuration...")
	try:
		fp = open(CONF_FILE, "w")
		fp.write(dati)
		fp.close()
	except:
		print_error("Error in I/O "+CONF_FILE)
	sys.exit()
	print(CONF_FILE+" saved.")


def print_help():
	print("\n\t** whiteprocess **")
	print("\tAuthor: Stefano Gorresio")
	print("\tVersion: PyELF beta 0.8")
	print("\tLicense: GPLv3\n")
	print("Arguments:")
	print("help\t\t\tShow this message.")
	print("start\t\t\tStart service.")
	print("stop\t\t\tStop service.")
	print("autoconf\t\tGuided configuration.")
	print("check_status\t\tPrint whiteprocess status.")
	print("check_exe\t\tPrint running executables.")
	print("check_cmd\t\tPrint running commands.")
	print("reset_status\t\tReset status to \"stopped\".")
	print("reset_conf\t\tReset configuration file.")
	print("")
	sys.exit()


def exclude_path(exe_allow, path):
	exe_excluded = 0
	for file in os.listdir(path):
		fullpath = path+file
		if os.path.isfile(fullpath) and os.access(fullpath, os.X_OK):
			exe_excluded += 1
			exe_allow.append(fullpath)
	return exe_allow, exe_excluded


### REMOTE CHECK ###


class ClientThread(threading.Thread): 

	wp_proto = None
 
	def __init__(self, wp_proto, sock): 
		threading.Thread.__init__(self) 
		self.wp_proto = wp_proto
		self.wp_proto.sock = sock
 
	def run(self):
		wp_proto.respond_to_request()


def server_init(porta, wp_proto):
	try:
		sockServer = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
		sockServer.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) 
		sockServer.bind(("", porta))
		sockServer.listen(4)
	except:
		add_log("Listening on " + str(porta) + ":tcp failed. Socket in use?", configurations.LOG_FILE)
		sys.exit()
	threads = []
	add_log("Listening " + str(porta) + ":tcp ...", configurations.LOG_FILE)
	while True: 
		(sock, addr) = sockServer.accept()
		add_log(addr[0] + ":" + str(addr[1]) + " connected.", configurations.LOG_FILE)
		sock.settimeout(30)
		session = ClientThread(wp_proto, sock)
		session.start() 
		threads.append(session)

### MAIN ###

if __name__ == "__main__":
	
	# Load configurations
	configurations = whiteprocess_configurations()
	wp_status = whiteprocess_status(configurations.STATUS_FILE)
	
	# Check if root
	if not os.geteuid() == 0:
		print_error("whiteprocess must be run as root.")
	
	# Parse arguments
	try:
		arg = sys.argv[1]
	except:
		print("For info type \"whiteprocess help\"")
		sys.exit()
	if arg == "help":
		print_help()
	elif arg == "autoconf":
		autoconf(configurations.CONF_FILE, configurations.WP_DIRECTORY)
	elif arg == "check_exe":
		check_process()
		sys.exit()
	elif arg == "check_cmd":
		check_commands()
	elif arg == "reset_status":
		wp_status.set("S,0")
		print("whiteprocess set to \"stopped\".")
		sys.exit()
	elif arg == "reset_conf":
		if os.system("cp "+configurations.WP_DIRECTORY+"whiteprocess.conf "+configurations.CONF_FILE) == 0:
			print(configurations.CONF_FILE+" resetted.")
			sys.exit()
		else:
			print_error("Problem with reset configuration file.")
	elif arg == "check_status":
		stat = wp_status.get().split(",")
		if stat[0] == "R":
			print("whiteprocess is running with PID "+stat[1])
			sys.exit()
		elif stat[0] == "S":
			print("whiteprocess is not running.")
			sys.exit()
		else:
			print_error(configurations.STATUS_FILE+" is corrupted.")
	elif arg == "stop":
		if configurations.USE_PASSWORD:
			password = getpass.getpass()
			if not hash_string(password) == configurations.PASSWORD:
				print_error("Password is wrong.")
		stat = wp_status.get().split(",")
		if stat[0] == "R":
			try:
				psutil.Process(int(stat[1])).kill()	# Kill whiteprocess
			except:
				print("ERROR: Process with PID "+stat[1]+" not found.")
				print("whiteprocess might have been killed forcedly")
				print("Type \"whiteprocess reset_status\" and retry.")
				sys.exit()
			wp_status.set("S,0")
			add_log("whiteprocess service stopped (PID "+stat[1]+").", configurations.LOG_FILE)
			print("whiteprocess stopped.")
			sys.exit()
		else:
			print_error("whiteprocess not running.")
	elif arg == "start":
		# Check if can run.
		stat = wp_status.get().split(",")
		if stat[0] == "R":
			add_log("\nwhiteprocess is already running...", configurations.LOG_FILE)
			sys.exit()
			
		print("Time Check: "+str(configurations.TIME_CHECK)+" seconds.")
		add_log("Time Check: "+str(configurations.TIME_CHECK)+" seconds.", configurations.LOG_FILE)
		
		if configurations.REMOTE_CHECK:
			print("Remote Check in "+str(configurations.TCP_PORT)+":tcp port.")
			add_log("Remote Check in "+str(configurations.TCP_PORT)+":tcp port.", configurations.LOG_FILE)
			wp_proto = whiteprocess_proto(None, configurations.LOG_FILE, configurations.EXE_ALLOW.main_list)
			threading.Thread(target=server_init, args=(configurations.TCP_PORT, wp_proto,)).start()
			print("Remote Check running...")
		
		for path in configurations.PATH_ALLOW.main_list:
			configurations.EXE_ALLOW.main_list, exe_excluded = exclude_path(configurations.EXE_ALLOW.main_list, path)
			print("Not filtering '"+path+"*' ("+str(exe_excluded)+" executables added in whitelist)...")
			add_log("Executables allowed in '"+path+"*'", configurations.LOG_FILE)
		if arg == "start":
			print("Total executables allowed to run: "+str(len(configurations.EXE_ALLOW.main_list)))
		add_log("Total executables allowed to run: "+str(len(configurations.EXE_ALLOW.main_list)), configurations.LOG_FILE)
		
		if configurations.EXE_FILTER:
			print("Executables Filter running...")
			add_log("Executables Filter running...", configurations.LOG_FILE)
		if configurations.ARGS_FILTER:
			print("Arguments Filter running...")
			add_log("Arguments Filter running...", configurations.LOG_FILE)
		if configurations.AFTER_EXEC_FILTER:
			print("After Execution Filter running...")
			add_log("After Execution Filter running...", configurations.LOG_FILE)
	else:
		print("For info type \"whiteprocess help\"")
		sys.exit()
	
	main_agent(configurations.LOG_FILE, configurations.TIME_CHECK, wp_status, configurations.EXE_FILTER, configurations.ARGS_FILTER, configurations.AFTER_EXEC_FILTER, configurations.EXE_ALLOW.main_list, configurations.ARGS_ALLOW.main_list, configurations.AFTER_EXEC_KILL.main_list)
