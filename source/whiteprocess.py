#               whiteprocess (alpha 0.1) : White List Process Filter
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
TIME_CHECK = 0


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

def print_status(testo):
	#print(testo)
	add_log(testo)

def read_conf_file():
	global TIME_CHECK
	global LOG_FILE
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
	for i in range(len(row)):
		pez = row[i].split("=")
		if row[i] == "EXE_ALLOW{":
			j = i + 1
			process_allow = []
			while row[j] != "}":
				process_allow.append(row[j])
				j += 1
		elif pez[0] == "TIME_CHECK":
			TIME_CHECK = int(pez[1])
		elif pez[0] == "LOG_FILE":
			LOG_FILE = pez[1]
	return process_allow

def print_help():
	print("\n\t** whiteprocess **")
	print("\tAuthor: Stefano Gorresio")
	print("\tVersion: alpha 0.1")
	print("\tLicense: GPLv3\n")
	print("Arguments:")
	print("help\t\tShow this message.")
	print("start\t\tStart service.")
	print("check\t\tPrint running executables.")
	print("")
	exit()

def check_process():
	exes = []
	for i in psutil.pids():
		p = psutil.Process(i)
		if (p.exe() not in exes) and (p.exe() != ""):
			exes.append(p.exe())
	# Print info
	print("Found "+str(len(exes))+" executable running:")
	for i in exes:
		print(i)
	exit()

def main():
	# Read config file
	process_allow = read_conf_file()
	# Check if root
	if not os.geteuid() == 0:
		print("ERROR: whiteprocess must be run as root.")
		exit()
	# Parse arguments
	try:
		arg = sys.argv[1]
	except:
		print("ERROR: For info type \"whiteprocess help\"")
		exit()
	if arg == "help":
		print_help()
	elif arg == "check":
		check_process()
	elif not arg == "start":
		print("For info type \"whiteprocess help\"")
		exit()
		
	# Running...
	print("whiteprocess started...")
	print_status("whiteprocess service started...")
	while True:		
		for i in psutil.pids():
			p = psutil.Process(i)
			kill = True
			if (p.exe() in process_allow) or (p.exe() == ""):
				kill = False
			if kill:
				p.kill()
				print_status("Killed process PID "+str(i)+"   Exe: "+p.exe())
		time.sleep(TIME_CHECK)


if __name__ == "__main__":
	main()
