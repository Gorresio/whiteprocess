#               whiteprocess (alpha 0.3) : White List Process Filter
#
#                  Copyright (C) 2017 Stefano Gorresio
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
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

# Global Variables
CONF_FILE = "/etc/whiteprocess.conf"
LOG_FILE = ""
STATUS_FILE = "/usr/share/whiteprocess/whiteprocess.status"
TIME_CHECK = 0
EXE_FILTER = False
ARGS_FILTER = False
AFTER_EXEC_FILTER = False


def localtime():
	return time.asctime(time.localtime(time.time()))



def add_log(testo):
	try:
		fp = open(LOG_FILE, "a")
		fp.write(localtime()+" - "+testo+"\n")
		fp.close()
	except:
		print("ERROR: Error in I/O "+LOG_FILE)
		exit()


def read_conf_file():
	global TIME_CHECK
	global LOG_FILE
	global EXE_FILTER
	global ARGS_FILTER
	global AFTER_EXEC_FILTER
	try:
		fp = open(CONF_FILE, "r")
		dati = fp.read()
		fp.close()
	except:
		print("ERROR: Error in I/O "+CONF_FILE)
		exit()
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
				print("ERROR: "+CONF_FILE+" malformed: row:"+str(i)+" \""+row[i]+"\"")
				exit()
		elif pez[0] == "ARGS_FILTER":
			if pez[1] == "yes":
				ARGS_FILTER = True
			elif pez[1] == "no":
				ARGS_FILTER = False
			else:
				print("ERROR: "+CONF_FILE+" malformed: row:"+str(i)+" \""+row[i]+"\"")
				exit()
		elif pez[0] == "AFTER_EXEC_FILTER":
			if pez[1] == "yes":
				AFTER_EXEC_FILTER = True
			elif pez[1] == "no":
				AFTER_EXEC_FILTER = False
			else:
				print("ERROR: "+CONF_FILE+" malformed: row:"+str(i)+" \""+row[i]+"\"")
				exit()
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
	return process_allow, args_allow, after_kill


def print_help():
	print("\n\t** whiteprocess **")
	print("\tAuthor: Stefano Gorresio")
	print("\tVersion: alpha 0.3")
	print("\tLicense: GPLv3\n")
	print("Arguments:")
	print("help\t\t\tShow this message.")
	print("start\t\t\tStart service.")
	print("stop\t\t\tStop service.")
	print("check_status\t\tPrint whiteprocess status.")
	print("check_exe\t\tPrint running executables.")
	print("check_cmd\t\tPrint running commands.")
	print("")
	exit()


def check_process():
	exes = []
	for i in psutil.pids():
		p = psutil.Process(i)
		if (p.exe() not in exes) and (p.exe() != ""):
			exes.append(p.exe())
	# Print info
	print("Found "+str(len(exes))+" executables running:")
	for i in exes:
		print(i)
	exit()


def check_commands():
	cmds = []
	for i in psutil.pids():
		p = psutil.Process(i)
		if (" ".join(p.cmdline()) not in cmds) and (p.exe() != ""):
			cmds.append(" ".join(p.cmdline()))
	# Print info
	print("Found "+str(len(cmds))+" commands running:")
	for i in cmds:
		print(i)
	exit()


def whiteprocess_set_status(status):	
	try:
		fp = open(STATUS_FILE, "w")
		dati = fp.write(status)
		fp.close()
	except:
		print("ERROR: Error in I/O "+STATUS_FILE)
		exit()


def whiteprocess_get_status():	
	try:
		fp = open(STATUS_FILE, "r")
		return fp.read()
	except:
		print("ERROR: Error in I/O "+STATUS_FILE)
		exit()


def main():
	# Read config file
	process_allow, args_allow, after_kill = read_conf_file()
	# Check if root
	if not os.geteuid() == 0:
		print("ERROR: whiteprocess must be run as root.")
		exit()
	# Parse arguments
	try:
		arg = sys.argv[1]
	except:
		print("For info type \"whiteprocess help\"")
		exit()
	if arg == "help":
		print_help()
	elif arg == "check_exe":
		check_process()
	elif arg == "check_cmd":
		check_commands()
	elif arg == "check_status":
		stat = whiteprocess_get_status().split(",")
		if stat[0] == "R":
			print("whiteprocess is running with PID "+stat[1])
			exit()
		elif stat[0] == "S":
			print("whiteprocess is not running.")
			exit()
		else:
			print("ERROR: "+STATUS_FILE+" is corrupted.")
			exit()
	elif arg == "stop":
		stat = whiteprocess_get_status().split(",")
		if stat[0] == "R":
			psutil.Process(int(stat[1])).kill()	# Kill whiteprocess
			whiteprocess_set_status("S,0")
			add_log("whiteprocess service stopped (PID "+stat[1]+").")
			print("whiteprocess stopped.")
			exit()
		else:
			print("ERROR: whiteprocess not running.")
			exit()
	elif not arg == "start":
		print("For info type \"whiteprocess help\"")
		exit()
	# Check if can run.
	stat = whiteprocess_get_status().split(",")
	if stat[0] == "R":
		print("ERROR: whiteprocess is already running...")
		exit()
	# Running...
	whiteprocess_set_status("R,"+str(os.getpid()))
	print("whiteprocess started (PID "+str(os.getpid())+") ...")
	add_log("whiteprocess service started (PID "+str(os.getpid())+") ...")
	print("Time Check: "+str(TIME_CHECK)+" seconds.")
	add_log("Time Check: "+str(TIME_CHECK)+" seconds.")
	if EXE_FILTER:
		print("Executables Filter running...")
		add_log("Executables Filter running...")
	if ARGS_FILTER:
		print("Arguments Filter running...")
		add_log("Arguments Filter running...")
	if AFTER_EXEC_FILTER:
		print("After Execution Filter running...")
		add_log("After Execution Filter running...")
	TIME_START = time.time()
	while True:		
		for i in psutil.pids():
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
			if AFTER_EXEC_FILTER and flag:
				if p.exe() in after_kill:
					if p.create_time() > TIME_START:
						kill = True
			if kill:
				p.kill()
				add_log("Killed process PID "+str(i)+"   Cmd: "+" ".join(args)+" ("+p.exe()+")")
		time.sleep(TIME_CHECK)


if __name__ == "__main__":
	main()
