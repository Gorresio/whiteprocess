#         whiteprocess (alpha 0.5) : Whitelist Threads Filter for UNIX
#
#                  Copyright (C) 2017 Stefano Gorresio
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

from whiteprocess_api import *
import sys
import os
import psutil
import time
import getpass


def read_conf_file(CONF_FILE, LOG_FILE, TIME_CHECK, EXE_FILTER, ARGS_FILTER, AFTER_EXEC_FILTER, REMOTE_CHECK, USE_PASSWORD, PASSWORD, UDP_PORT):
	try:
		fp = open(CONF_FILE, "r")
		dati = fp.read()
		fp.close()
	except:
		print_error("Error in I/O "+CONF_FILE)
	dati = dati.replace(" ", "")
	dati = dati.replace("\t", "")
	row = dati.split("\n")
	process_allow = []
	args_allow = []
	after_kill = []
	for i in range(len(row)):
		pez = row[i].split("=")
		if pez[0] == "TIME_CHECK":
			TIME_CHECK = int(pez[1])
		elif pez[0] == "LOG_FILE":
			LOG_FILE = pez[1]
		elif pez[0] == "EXE_FILTER":
			if pez[1] == "yes":
				EXE_FILTER = True
			elif pez[1] == "no":
				EXE_FILTER = False
			else:
				print_error(CONF_FILE+" malformed: row:"+str(i)+" \""+row[i]+"\"")
		elif pez[0] == "ARGS_FILTER":
			if pez[1] == "yes":
				ARGS_FILTER = True
			elif pez[1] == "no":
				ARGS_FILTER = False
			else:
				print_error(CONF_FILE+" malformed: row:"+str(i)+" \""+row[i]+"\"")
		elif pez[0] == "AFTER_EXEC_FILTER":
			if pez[1] == "yes":
				AFTER_EXEC_FILTER = True
			elif pez[1] == "no":
				AFTER_EXEC_FILTER = False
			else:
				print_error(CONF_FILE+" malformed: row:"+str(i)+" \""+row[i]+"\"")
		elif pez[0] == "USE_PASSWORD":
			if pez[1] == "yes":
				USE_PASSWORD = True
			elif pez[1] == "no":
				USE_PASSWORD = False
			else:
				print_error(CONF_FILE+" malformed: row:"+str(i)+" \""+row[i]+"\"")
		elif pez[0] == "REMOTE_CHECK":
			if pez[1] == "yes":
				REMOTE_CHECK = True
			elif pez[1] == "no":
				REMOTE_CHECK = False
			else:
				print_error(CONF_FILE+" malformed: row:"+str(i)+" \""+row[i]+"\"")
		if USE_PASSWORD:
			if pez[0] == "PASSWORD":
				PASSWORD = pez[1]
		if REMOTE_CHECK:
			if pez[0] == "UDP_PORT":
				UDP_PORT = int(pez[1])
		if EXE_FILTER:
			if row[i] == "EXE_ALLOW{":
				j = i + 1
				while row[j] != "}":
					process_allow.append(row[j])
					j += 1
		if ARGS_FILTER:
			if row[i] == "ARGS_ALLOW{":
				j = i + 1
				while row[j] != "}":
					args_allow.append(row[j].split(":"))
					j += 1
		if AFTER_EXEC_FILTER:
			if row[i] == "AFTER_EXEC_KILL{":
				j = i + 1
				while row[j] != "}":
					after_kill.append(row[j])
					j += 1
	return CONF_FILE, LOG_FILE, TIME_CHECK, EXE_FILTER, ARGS_FILTER, AFTER_EXEC_FILTER, REMOTE_CHECK, USE_PASSWORD, PASSWORD, UDP_PORT, process_allow, args_allow, after_kill


def print_help():
	print("\n\t** whiteprocess **")
	print("\tAuthor: Stefano Gorresio")
	print("\tVersion: alpha 0.5")
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
	exit()


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
	exit()


def whiteprocess_set_status(STATUS_FILE, status):	
	try:
		fp = open(STATUS_FILE, "w")
		dati = fp.write(status)
		fp.close()
	except:
		print_error("Error in I/O "+STATUS_FILE)


def whiteprocess_get_status(STATUS_FILE):	
	try:
		fp = open(STATUS_FILE, "r")
		return fp.read()
	except:
		print_error("Error in I/O "+STATUS_FILE)


### AUTOCONF ###

def auto_check_exe(dati):
	exes = check_process()
	stringa = ""
	for i in exes:
		stringa += "\n"+i
	dati = dati.replace("EXE_ALLOW{\n\n}", "EXE_ALLOW{"+stringa+"\n}")
	return dati
	

def autoconf(CONF_FILE, WP_DIRECTORY):
	print("\n\t** whiteprocess Guided Configuration **")
	
	answer = raw_input("\nDo you want reset config file? (yes/no): ")
	if answer == "yes":	
		if os.system("cp "+WP_DIRECTORY+"whiteprocess.conf "+CONF_FILE) == 0:
			print(CONF_FILE+" resetted.")
		else:
			print_error("Problem with reset configuration file.")
	elif answer == "no":
		print("If you do not reset the config file, you will not continue.\nExit.")
		exit()
	else:
		print("Invalid answer. Considered \"no\".")
		print("If you do not reset the config file, you will not continue.\nExit.")
		exit()
	
	try:
		fp = open(CONF_FILE, "r")
		dati = fp.read()
		fp.close()
	except:
		print_error("Error in I/O "+CONF_FILE)
	
	answer = raw_input("\nDo you want insert in executables allowed (EXE_FILTER) current executables running? (yes/no): ")
	if answer == "yes":
		dati = auto_check_exe(dati)
	elif answer == "no":
		pass
	else:
		print("Invalid answer. Considered \"no\".")
	
	answer = raw_input("\nDo you want enable Arguments Filter? (yes/no): ")
	if answer == "yes":
		dati = dati.replace("ARGS_FILTER = no", "ARGS_FILTER = yes")
		print("Arguments Filter enabled... ARGS_ALLOW must be filled manually.")
	elif answer == "no":
		pass
	else:
		print("Invalid answer. Considered \"no\".")
	
	answer = raw_input("\nDo you want enable After Exec Filter? (yes/no): ")
	if answer == "yes":
		dati = dati.replace("AFTER_EXEC_FILTER = no", "AFTER_EXEC_FILTER = yes")
		print("After Exec Filter enabled... AFTER_EXEC_KILL must be filled manually.")
	elif answer == "no":
		pass
	else:
		print("Invalid answer. Considered \"no\".")
	
	answer = raw_input("\nTime in second from one control to another? (Default: 5): ")
	if not answer == "":
		try:
			int(answer)
			dati = dati.replace("TIME_CHECK = 5", "TIME_CHECK = "+answer)
			print("Time setted to "+answer+" seconds.")
		except:
			print("Invalid input: must be an integer.")
			print("Time setted to 5 seconds.")
	else:
		print("Time setted to 5 seconds.")
	
	answer = raw_input("\nDo you want enable Password for stopping service? (yes/no): ")
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
				dati = dati.replace("PASSWORD = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "PASSWORD = "+hash_string(password))
				flag = False
			else:
				print("Password not matched. Retry.\n")
		print("Password saved.")
	elif answer == "no":
		pass
	else:
		print("Invalid answer. Considered \"no\".")
	
	answer = raw_input("\nDo you want enable Remote Control? (yes/no): ")
	if answer == "yes":
		dati = dati.replace("REMOTE_CHECK = no", "REMOTE_CHECK = yes")
		answer = raw_input("\nInsert UDP port to listening? (Default: 2357): ")
		if not answer == "":
			try:
				int(answer)
				dati = dati.replace("UDP_PORT = 2357", "UDP_PORT = "+answer)
				print("UDP port setted to "+answer+".")
			except:
				print("Invalid input: must be an integer.")
				print("UDP port setted to 2357.")
		else:
			print("UDP port setted to 2357.")
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
	exit()
	print(CONF_FILE+" saved.")



### MAIN ###

def main():
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
	UDP_PORT = 0
	
	# Read config file
	CONF_FILE, LOG_FILE, TIME_CHECK, EXE_FILTER, ARGS_FILTER, AFTER_EXEC_FILTER, REMOTE_CHECK, USE_PASSWORD, PASSWORD, UDP_PORT, process_allow, args_allow, after_kill = read_conf_file(CONF_FILE, LOG_FILE, TIME_CHECK, EXE_FILTER, ARGS_FILTER, AFTER_EXEC_FILTER, REMOTE_CHECK, USE_PASSWORD, PASSWORD, UDP_PORT)
	
	# Check if root
	if not os.geteuid() == 0:
		print_error("whiteprocess must be run as root.")
	
	# Parse arguments
	try:
		arg = sys.argv[1]
	except:
		print("For info type \"whiteprocess help\"")
		exit()
	if arg == "help":
		print_help()
	elif arg == "autoconf":
		autoconf(CONF_FILE, WP_DIRECTORY)
	elif arg == "check_exe":
		check_process()
		exit()
	elif arg == "check_cmd":
		check_commands()
	elif arg == "reset_status":
		whiteprocess_set_status(STATUS_FILE, "S,0")
		print("whiteprocess set to \"stopped\".")
		exit()
	elif arg == "reset_conf":
		if os.system("cp "+WP_DIRECTORY+"whiteprocess.conf "+CONF_FILE) == 0:
			print(CONF_FILE+" resetted.")
			exit()
		else:
			print_error("Problem with reset configuration file.")
	elif arg == "check_status":
		stat = whiteprocess_get_status(STATUS_FILE).split(",")
		if stat[0] == "R":
			print("whiteprocess is running with PID "+stat[1])
			exit()
		elif stat[0] == "S":
			print("whiteprocess is not running.")
			exit()
		else:
			print_error(STATUS_FILE+" is corrupted.")
	elif arg == "stop":
		if USE_PASSWORD:
			password = getpass.getpass()
			if not hash_string(password) == PASSWORD:
				print_error("Password is wrong.")
		stat = whiteprocess_get_status(STATUS_FILE).split(",")
		if stat[0] == "R":
			try:
				psutil.Process(int(stat[1])).kill()	# Kill whiteprocess
			except:
				print("ERROR: Process with PID "+stat[1]+" not found.")
				print("whiteprocess might have been killed forcedly")
				print("Type \"whiteprocess reset_status\" and retry.")
				exit()
			whiteprocess_set_status(STATUS_FILE, "S,0")
			add_log("whiteprocess service stopped (PID "+stat[1]+").", LOG_FILE)
			print("whiteprocess stopped.")
			exit()
		else:
			print_error("whiteprocess not running.")
	elif not arg == "start":
		print("For info type \"whiteprocess help\"")
		exit()
	
	# Check if can run.
	stat = whiteprocess_get_status(STATUS_FILE).split(",")
	if stat[0] == "R":
		print_error("whiteprocess is already running...")
        
	# Running...
	whiteprocess_set_status(STATUS_FILE, "R,"+str(os.getpid()))
	print("whiteprocess started (PID "+str(os.getpid())+") ...")
	add_log("whiteprocess service started (PID "+str(os.getpid())+") ...", LOG_FILE)
	print("Time Check: "+str(TIME_CHECK)+" seconds.")
	add_log("Time Check: "+str(TIME_CHECK)+" seconds.", LOG_FILE)
	
	if REMOTE_CHECK:
		print("Remote Check in "+str(UDP_PORT)+":udp port.")
		add_log("Remote Check in "+str(UDP_PORT)+":udp port.", LOG_FILE)
		sock_server_init(UDP_PORT)	# Start UDP server thread
	
	if EXE_FILTER:
		print("Executables Filter running...")
		add_log("Executables Filter running...", LOG_FILE)
	if ARGS_FILTER:
		print("Arguments Filter running...")
		add_log("Arguments Filter running...", LOG_FILE)
	if AFTER_EXEC_FILTER:
		print("After Execution Filter running...")
		add_log("After Execution Filter running...", LOG_FILE)
	
	TIME_START = time.time()
	
	while True:
		pids_list = psutil.pids()
		if pids_list[len(pids_list)-1] == 0:    # Exclude PID 0 (BSD kernel)
			pids_list.pop()
		for i in pids_list:
			try:
				p = psutil.Process(i)
				args = p.cmdline()
				kill = True
				flag = True
				if p.exe() == "":		# Skip kernel threads
					kill = False
					flag = False
				if EXE_FILTER and flag:		# Exe Filter
					if p.exe() in process_allow:
						kill = False
				if ARGS_FILTER and flag:	# Args Filter
					for j in args_allow:
						if p.exe() == j[0]:
							argv = j[1].split(",")
							for k in range(len(argv)):
								try:
									if not args[k+1] == argv[k]:
										kill = True
								except:	# List out of range
									kill = True
				if AFTER_EXEC_FILTER and flag:	# After Exec Filter
					if p.exe() in after_kill:
						if p.create_time() > TIME_START:
							kill = True
				if kill:
					p.kill()
					add_log("Killed process PID "+str(i)+"   Cmd: "+" ".join(args)+" ("+p.exe()+")", LOG_FILE)
			except:		# For avoid some conditions
				break
		time.sleep(TIME_CHECK)


if __name__ == "__main__":
	main()
