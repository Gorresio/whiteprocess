# whiteprocess (alpha 0.5) - Whitelist Process on UNIX (GNU/Linux and BSD)


Full documentation and analysis:   http://ciaparath.altervista.org/publish/whiteprocess_A0.5_doc.pdf

For testing:   http://ciaparath.altervista.org/trytohack_whiteprocess.html


### - General Functioning

whiteprocess is a simple software (for now it is in alpha version) programmed in Python 2.7 for UNIX systems which is used to filter threads in white list.

Its purpose is to optimize the work that antivirus offers, performing a filtering of all process/threads that the user did not declare to be “allowed” to run.

whiteprocess replaces antivirus on server.


Its functioning is very simple:

When started, it read various lists (executables, arguments, ecc.) and various parameters from configuration file (default /etc/whiteprocess.conf).

Periodically, it control if each thread respects the conditions declared in config file. If a thread doesn’t respect the conditions, whiteprocess kills it.

The kernel threads will not be taken into account.

Time from one control to another and what controls should be done, are managed by configuration file.

All operations are recorded on log file (default /var/log/whiteprocess.log).

whiteprocess must be run as root and in background.

As you can easily notice, it runs in user mode.





### - Installation and Uninstallation

Before install whiteprocess, its dependencies must be installed.

Its dependencies are *python2.7* and *python-psutil*.

The installation process create:
 - configuration file: /etc/whiteprocess.conf
 - directory: /usr/share/whiteprocess/
 - compiling python script and put them in /usr/share/whiteprocess/
 - status file:  /usr/share/whiteprocess/whiteprocess.status
 - template config file:  /usr/share/whiteprocess/whiteprocess.conf
 - sh script: /bin/whiteprocess

The uninstallation process remove all except log file.



For install whiteprocess download the source and in ./whiteprocess/ directory type **./install** command with root permission.

For uninstall whiteprocess in ./whiteprocess/ directory type **./uninstall** command with root permission.

If install and uninstall script generate error how *Permission Denied* or *./install: command not found*, Make sure that of correct permission and if the scripts are marked as executable (if not, type **chmod +x install uninstall** command in ./whiteprocess/).



### - Use of whiteprocess

Before start the service, configuration file must be configured.

To find executables running type **whiteprocess check_exe** command with root permission.

To find commands running type **whiteprocess check_cmd** command with root permission.

To configure whiteprocess there are two options: manual configuration and guided configuration.

For execute the guided configuration run **whiteprocess autoconf** with root permission.

Once the configuration file has been completed, you can start the daemon with command **whiteprocess start** how root.

For terminate the service is sufficient type **whiteprocess stop** how root or kill the process (python2.7 /usr/share/whiteprocess/whiteprocess.pyc start) with program how htop, etc. or reboot the system.

If whiteprocess is killed forcedly without appropriate command, it is necessary execute **whiteprocess reset_status** how root for execute again the service.


### - Future Development
The following points could be developed in the future:
- Improve “user experience”
- Add remote check 
- Automate some procedures
- Prevention execution instead of kill after execution
- Conversion from script to binary (from Python to C)

### - Version History
whiteprocess alpha 0.5
- Added autoconf function
- Added password for stopping service
- Added reset configuration
- Added reset status (for manage irregular stops)
- Improved "user experience"
- Corrected some bugs
- Optimized source code
- Use of */bin/sh* instead of */bin/bash* in scripts

whiteprocess alpha 0.3
- Added stopping function
- Added arguments filter
- Added after exec filter
- Optimized scanning algorithm
- Added info to log file
- Improved "user experience"

whiteprocess alpha 0.1
- Added installation and uninstallation script
- Added executables filter
- Publish whiteprocess

### - Note

whiteprocess is a free software licensed by GPLv3.

Copy of GPLv3 license is present in ./LICENSE file


If you notice any violations by myself or by third parties, please contact me at stefano.gorresio@null.net

Violations of the use of whiteprocess could be legally prosecutable.

*I know, source code for now is a bit messy XD*


Stefano Gorresio

Email: stefano.gorresio@null.net


