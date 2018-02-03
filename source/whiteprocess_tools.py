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
import socket
from whiteprocess_socket import *


def help():
	print("\n\t** whiteprocess Tools **")
	print("\tAuthor: Stefano Gorresio")
	print("\tVersion: 0.1")
	print("\tLicense: GPLv3\n")
	print("Use: whiteprocess_tools <command> [extra arguments]\n")
	print("Command:")
	print("check <host> <port>\t\t\tCheck remote running whiteprocess (alive control).")
	print("getlog <host> <port> <last lines>\t\tGet last logs.")
	print("exe_allowed <host> <port>\t\t\tGet list of allowed executables.")
	print("help\t\t\t\tShow this message.")
	print("")
	sys.exit()


def connect(remote_host, remote_port):
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	sock.settimeout(30.0)
	sock.connect((remote_host, int(remote_port)))
	return whiteprocess_proto(sock)


if __name__ == "__main__":
	try:
		command = sys.argv[1]
	except:
		help()
	if command == "help":
		help() 
	elif command == "check":
		try:
			remote_host = sys.argv[2]
			remote_port = int(sys.argv[3])
		except:
			print("Use: whiteprocess_tools check <host> <port>")
			sys.exit()
		print("Connection to "+remote_host+":"+str(remote_port)+" ...")
		try:
			wp_proto = connect(remote_host, remote_port)
			stato = wp_proto.check_alive()
			if stato == 2:
				print("Invalid response. Correct TCP socket?")
			elif stato == True:
				print("whiteprocess on "+remote_host+":"+str(remote_port)+" is running.")
			else:
				print("Connection to "+remote_host+":"+str(remote_port)+" failed.")
		except:
			print("Connection to "+remote_host+":"+str(remote_port)+" failed.")
	elif command == "getlog":
		try:
			remote_host = sys.argv[2]
			remote_port = int(sys.argv[3])
			lines = sys.argv[4]
		except:
			print("Use: whiteprocess_tools getlog <host> <port> <last lines>")
			sys.exit()
		try:
			wp_proto = connect(remote_host, str(remote_port))
			risp = wp_proto.get_log(lines)
			if risp == 2:
				print("Invalid response. Correct TCP socket?")
			elif risp == False:
				print("Connection to "+remote_host+":"+str(remote_port)+" failed.")
			else:
				for line in risp[:-1]:
					print(line)
		except:
			print("Connection to "+remote_host+":"+str(remote_port)+" failed.")
	elif command == "exe_allowed":
		try:
			remote_host = sys.argv[2]
			remote_port = int(sys.argv[3])
		except:
			print("Use: whiteprocess_tools exe_allowed <host> <port>")
			sys.exit()
		try:
			wp_proto = connect(remote_host, remote_port)
			risp = wp_proto.check_exe_allowed()
			if risp == 2:
				print("Invalid response. Correct TCP socket?")
			elif risp == False:
				print("Connection to "+remote_host+":"+str(remote_port)+" failed.")
			else:
				for exe in risp[:-1]:
					print(exe)
		except:
			print("Connection to "+remote_host+":"+str(remote_port)+" failed.")
	else:
		print("ERROR: Invalid argument")
		help()
