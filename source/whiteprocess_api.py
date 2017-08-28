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

import time
import hashlib


def localtime():
	return time.asctime(time.localtime(time.time()))


def print_error(testo):
	print("ERROR: "+testo)
	exit()


def add_log(testo, LOG_FILE):
	try:
		fp = open(LOG_FILE, "a")
		fp.write(localtime()+" - "+testo+"\n")
		fp.close()
	except:
		print_error("Error in I/O "+LOG_FILE)


def hash_string(stringa):
	return hashlib.sha256(stringa).hexdigest()

