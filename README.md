
# whiteprocess (PyELF beta 0.8) - Whitelist Threads Filter on UNIX (GNU/Linux and BSD)


* Full documentation and analysis:   [whiteprocess\_PyELF\_B0.8\_doc.pdf](http://ciaparath.altervista.org/publish/whiteprocess\_PyELF\_B0.8\_doc.pdf)

* For testing:   [Try to Hack whiteprocess](http://ciaparath.altervista.org/trytohack\_whiteprocess.html)


### - General Functioning

**whiteprocess** is a simple software (for now it is in beta version) programmed in Python 2.7 and compiled in ELF for UNIX systems which is used to filter threads in whitelist.

Its purpose is to optimize the work that antivirus offers, performing a filtering of all process/threads that the user did not declare to be "allowed" to run.

whiteprocess replaces antivirus on server.

Its objectives are:

- Blocking malwares and unwanted threads (executables and scripts)
- Blocking buffer overflow attacks
- Regularly check the running threads
- Offer a user-friendly security system

Its functioning is very simple:

When started, it read various lists (executables, arguments, ecc.) and various parameters from configuration file (default /etc/whiteprocess.conf).

Periodically, it control if each thread respects the conditions declared in config file. If a thread doesn’t respect the conditions, whiteprocess kills it.

The kernel threads will not be taken into account.

Time from one control to another and what controls should be done, are managed by configuration file.

All operations are recorded on log file (default /var/log/whiteprocess.log).

whiteprocess must be run as root and in background.

As you can easily notice, it runs in user mode.


### - Installation and Uninstallation

For install whiteprocess, download the package and run the installer

```
# ./install
```

For uninstall whiteprocess, run the uninstaller

```
# ./uninstall
```


If install and uninstall script generate error how *Permission Denied* or *./install: command not found*, Make sure that of correct permission and if the scripts are marked as executable.

If not, type:

```
$ chmod +x install uninstall
```



### - Basic Use of whiteprocess

Before start the service, configuration file must be configured.

Auto configuration with:

```
# whiteprocess autoconf
```

Once corretly configured, for run it in daemon mode (also in boot), execute:

```
# whiteprocessd start
```

For stop it:

```
# whiteprocessd stop
```

### - Future Development
The following points could be developed in the future:

- Perform complete and exhaustive performance and robustness tests.
- Insert TLS in whiteprocess network communications.
- Divide agents into different executables to lighten primary memory.
- Prevention execution instead of kill after execution.
- Improve "user experience".
- Improve "remote management".
- Simplification and organization of source codes
- In case of big updates, an automatic update script will be issued.

### - FAQ
**Can you use whiteprocess in a production environment?**

Yes. From the beta version, whiteprocess can be used safely in production environments (it is still better to verify the correct operation in test environments).

Remote Control is still experimental.

Before starting whiteprocess make sure that configurations are all correct.

**Can whiteprocess cause a Denial of Service if badly configured?**

Absolutely yes, if you try to run whiteprocess without first configuring it, the operating system will be unusable (must be restarted).

**What is the best value to use for TIME\_CHECK?**

It depends. I use 0.5 seconds (the use of the CPU is not very high and the threads are not allowed to be eliminated almost instantly).

**Switching between successive versions how does it work?**

From now on, for each update, a script that will automatically update whiteprocess will be released (during the update it will have to be turned off).

**Will whiteprocess always be open source?**

whiteprocess is a computer security software and making it close source would be a contradiction.

whiteprocess will always be open source and its maintenance will always be free.

**Will there be whiteprocess for Microsoft Windows Server?**

whiteprocess is a brutal thread filtering software that works in whitelist.

MS Windows has a structure of permissions and threads management that would make whiteprocess not very effective.

For now it is not planned to create this software for MS Windows, but in the future...

### - Note

whiteprocess is a free software licensed by GPLv3.

Copy of GPLv3 license is present in ./LICENSE file


If you notice any violations by myself or by third parties, please contact me.

Serious violations of the use of whiteprocess source code could be legally prosecutable.

*I know, source code for now is a bit messy XD (see documentation)*

The use of whiteprocess is at your own risk: read the documentation before using it in production environments.

Stefano Gorresio

Email: stefano.gorresio@null.net


### - Version History
whiteprocess PyELF beta 0.8

- Eliminated all external dependencies
- Added remote management (still experimental)
- Added whitelist directory
- Added real daemon mode
- Changed structure
- Corrected some bugs
- Ordained source code

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
