# whiteprocess (alpha 0.1)- White List Process Filter


Full documentation and analysis:   http://ciaparath.altervista.org/publish/whiteprocess_doc.pdf


**Update 24 July 2017**: The development of this project is currently continuing.


### - General Functioning

whiteprocess is a simple software (for now it is in alpha version) programmed in Python 2.7 for UNIX systems which is used to filter threads in white list.


Its functioning is very simple:

When started, it read executables list (executable allowed) and various parameters from configuration file (default /etc/whiteprocess.conf).

Periodically, it control if an unlisted executable is running. If it is present, whiteprocess kills it.

The kernel threads will not be taken into account.

Time from one control to another is managed by configuration file.

All operations are recorded on log file (default /var/log/whiteprocess.log).

whiteprocess must be run as root and in background.

As you can easily notice, it runs in user mode.




### - Installation and Uninstallation

Before install whiteprocess, its dependencies must be installed.

Its dependencies are *python2.7* and *python-psutil*.

The installation process create:
 - configuration file: /etc/whiteprocess.conf
 - directory and python script: /usr/share/whiteprocess/whiteprocess.py
 - sh script: /bin/whiteprocess

The uninstallation process remove all except log file.


For install whiteprocess download the source and in ./whiteprocess/ directory type **./install** command with root permission.

For uninstall whiteprocess in ./whiteprocess/ directory type **./uninstall** command with root permission.




### - Use of whiteprocess

Before start the service, configuration file must be configured.

To find executables running type **whiteprocess check** command with root permission.

Once the configuration file has been completed, you can start the daemon
with command **whiteprocess start** how root.

For terminate the service is sufficient kill the process (python2.7 /usr/share/whiteprocess/whiteprocess.py start) with program how htop, etc. or reboot the system.

### - Future Development
The following points could be developed in the future:
- Adding stopping function
- Control child threads (more protection for script malwares and some buffer overflow attacks)
- Cross checks arguments of executables (lock script malwares)
- Prevention execution instead of kill after execution
- Conversion from script to binary (from Python to C)

### - Note

whiteprocess is a free software licensed by GPLv3.

Copy of GPLv3 license is present in ./LICENSE file


If you notice any violations by myself or by third parties, please contact me at stefano.gorresio@null.net

Violations of the use of whiteprocess could be legally prosecutable.



Stefano Gorresio

Email: stefano.gorresio@null.net
