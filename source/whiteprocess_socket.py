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

import time
import socket

class whiteprocess_proto():
	
	sock = None
	logfile = None
	exe_allow = None
	
	def __init__(self, sock, logfile = None, exe_allow = None):
		self.sock = sock
		self.logfile = logfile
		self.exe_allow = exe_allow
	
	
	def send_packet(self, data):
		try:
			self.sock.send("wp\x00"+data+"\xFF")
		except:
			return False
	
	
	def receive_packet(self):
		try:
			time.sleep(0.5)
			data = self.sock.recv(65536)
			if data[:3] == "wp\x00" and data[-1:] == "\xFF":
				return data[3:-1]
			else:
				return 2
		except:
			return False
	
	
	def check_alive(self):
		self.send_packet("ALIVE?")
		risp = self.receive_packet()
		if risp == "Y":
			return True
		return risp
	
	
	def get_log(self, rows):
		self.send_packet("LAST"+str(rows)+"LOG?")
		risp = self.receive_packet()
		if risp == 2 or risp == False:
			return risp
		return risp.replace("\n", "").split("\x00")
	
	
	def check_exe_allowed(self):
		self.send_packet("EXEALLOW?")
		risp = self.receive_packet()
		if risp == 2 or risp == False:
			return risp
		return risp.split("\x00")
	
	
	def respond_to_request(self):
		dati = self.receive_packet()
		if dati == False:
			return False
		elif dati == "ALIVE?":
			self.send_packet("Y")
		elif (dati[:4] == "LAST") and (dati[-4:] == "LOG?"):
			try:
				fp = open(self.logfile, "r")
				rows = fp.read().split("\n")
				fp.close()
			except:
				return False
			try:
				num = int(dati[4:-4])
			except:
				self.send_packet(2)
				return False
			logdata = ""
			for row in rows[-1*(num+1):]:
				logdata += row+"\x00"
			self.send_packet(logdata)
		elif dati == "EXEALLOW?":
			eseg = ""
			for exe in self.exe_allow:
				eseg += exe+"\x00"
			self.send_packet(eseg)
		else:
			self.send_packet(2)
