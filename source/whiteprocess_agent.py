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

import os
import time
import psutil
from whiteprocess_common import *

def main_agent(LOG_FILE, TIME_CHECK, wp_status, EXE_FILTER, ARGS_FILTER, AFTER_EXEC_FILTER, exe_allow, args_allow, after_exec_kill):
	
	# Running...
	wp_status.set("R,"+str(os.getpid()))
	add_log("whiteprocess service started (PID "+str(os.getpid())+") ...", LOG_FILE)
	
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
					if p.exe() in exe_allow:
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
					if p.exe() in after_exec_kill:
						if p.create_time() > TIME_START:
							kill = True
				if kill:
					p.kill()
					add_log("Killed process PID "+str(i)+"   Cmd: "+" ".join(args)+" ("+p.exe()+")", LOG_FILE)
			except:		# For avoid some conditions
				break
		time.sleep(TIME_CHECK)
