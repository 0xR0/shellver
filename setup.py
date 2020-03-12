from __future__ import print_function
import argparse
import os
import stat
import pip
from time import sleep
from sys import platform
from shutil import copy2, rmtree
from distutils.dir_util import copy_tree


__author__ = "0xR00T"
__version__ = "0.1"


# installation directory PATHs
FILE_PATH_LINUX = "/usr/share/shellver"
EXEC_PATH_LINUX = "/usr/bin/shellver"


def metadata():
	print("Shellver <0.1> by {}".format(__author__))
	print("Reverse Shell Cheat Sheet to do")
	print("Other cyber-warrior.org")

def dependencies(option):
    """install script dependencies with pip"""

    try:
        with open("requirements.txt", "r") as requirements:
            dependencies = requirements.read().splitlines()
    except IOError:
        print("requirements.txt not found, please redownload or do pull request again")
        exit(1)

    


def install(file_path, exec_path):
    """full installation of shellver to the system"""

    os.mkdir(file_path)
    copy2("shellver.py", file_path)
    copy2("requirements.txt", file_path)
    copy2("README.md", file_path)

    # python dependencies with pip
    dependencies("install")

    # add executable
    with open(exec_path, 'w') as installer:
        installer.write('#!/bin/bash\n')
        installer.write('\n')
        installer.write('python {}/shellver.py "$@"\n'.format(file_path))

    # S_IRWXU = rwx for owner
    # S_IRGRP | S_IXGRP = rx for group
    # S_IROTH | S_IXOTH = rx for other
    os.chmod(exec_path, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)


def uninstall(file_path, exec_path):
    """uninstall shellver from the system"""

    if os.path.exists(file_path):
        rmtree(file_path)
        print("Removed " + file_path)

    if os.path.isfile(exec_path):
        os.remove(exec_path)
        print("Removed " + exec_path)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--install", help="install shellver in the system",  action='store_true')
    parser.add_argument("-r", "--reinstall", help="remove old files and reinstall to the system", action="store_true")
    parser.add_argument("-u", "--uninstall", help="uninstall shellver from the system", action="store_true")
    args = parser.parse_args()

    if platform == "linux" or platform == "linux2":
        # Linux require root
        if os.getuid() != 0:
            print("linux system requires root access for the installation")
            exit(1)

        FILE_PATH = FILE_PATH_LINUX
        EXEC_PATH = EXEC_PATH_LINUX

    

    else:
        print("Windows platform is not supported for installation")
        exit(1)

    if args.install and not (args.reinstall or args.uninstall):
        #full installation to the system

        if os.path.exists(FILE_PATH):
            print("shellver is already installed under " + FILE_PATH)
            exit(1)

        if os.path.isfile(EXEC_PATH):
            print("executable file exists under " + EXEC_PATH)
            exit(1)

        install(FILE_PATH, EXEC_PATH)
        print("Installation finished")
        print("Files are installed under " + FILE_PATH)
	sleep(2)
        os.system('shellver how')

    elif args.uninstall and not (args.install or args.reinstall):
        # uninstall from the system

        uninstall(FILE_PATH, EXEC_PATH)
        
        print("Uninstallation finished")

    elif args.reinstall and not (args.install or args.uninstall):
        # reinstall to the system

        uninstall(FILE_PATH, EXEC_PATH)
        print("Removed previous installed files")

        install(FILE_PATH, EXEC_PATH)
        print("Reinstallation finished")
        print("Files are installed under " + FILE_PATH)
	sleep(2)
        os.system('shellver how')

    else:
        metadata(); print("")
        parser.print_help()
