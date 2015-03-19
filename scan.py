'''
	SCAN FOR VULNERABLE (HIJACKABLE) BINARIES
	scans the list of running processes or the entire file-system for applications that either
	1) contain a weak import (LC_LOAD_WEAK_DYLIB) that doesn't exist
	2) contain multiple run-path search paths, and a run-path import that doesn't exist in the primary search path

	NOTES:
	1) requires macholib
	2) this is proof-of-concept code ;)

'''


import os
import sys
import shlex
import argparse
import subprocess


#supported archs
SUPPORTED_ARCHITECTURES = ['i386', 'x86_64']

#executable binary
MH_EXECUTE = 2

#dylib
MH_DYLIB = 6

#bundles
MH_BUNDLE = 8

#make sure python version is ok
# ->and machO module is installed
def checkEnv():

	#global import
	global macholib

	#get python version
	pythonVersion = sys.version_info

	#check that python is at least 2.7
	if sys.version_info[0] == 2 and sys.version_info[1] < 7:

		#err msg
		print('ERROR: requires python 2.7+ (found: %s)' % (pythonVersion))

		#bail
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

		#bail
		return False

	#got to here
	# ->env looks ok!
	return True


#check for non intel architectures
# ->ensure things like iPhone files that are lying around aren't processed
def isSupportedArchitecture(macho):

	#flag
	supported = False

	#check macho headers for supported arch
	for machoHeader in macho.headers:

		#check
		if macholib.MachO.CPU_TYPE_NAMES.get(machoHeader.header.cputype, machoHeader.header.cputype) in SUPPORTED_ARCHITECTURES:

			#ok!
			supported = True

			#bail
			break

	return (supported, machoHeader)


#get list of loaded binaries
# ->'ps' sometimes doesn't give the full path, so we use lsof
def loadedBinaries():

	#list of loaded bins
	binaries = []

	#exec lsof
	lsof = subprocess.Popen('lsof /', shell=True, stdout=subprocess.PIPE)

	#get outpu
	output = lsof.stdout.read()

	#close
	lsof.stdout.close()

	#wait
	lsof.wait()

	#parse/split output
	# ->grab file name and check if its executable
	for line in output.split('\n'):

		try:

			#split on spaces up to 8th element
			# ->this is then the file name (which can have spaces so grab rest/join)
			binary = ' '.join(shlex.split(line)[8:])

			#skip non-files (fifos etc....) or non executable files
			if not os.path.isfile(binary) or not os.access(binary, os.X_OK):

				#skip
				continue

			#save binary
			binaries.append(binary)

		except:

			#ignore
			pass

	#filter out dup's
	binaries = list(set(binaries))

	return binaries


#list all mach-O binaries on the file-system
def installedBinaries(rootDirectory = None):

	#all executable binaries
	binaries = []

	#init
	if not rootDirectory:

		rootDirectory = '/'

	#recursively walk (starting at r00t)
	for root, dirnames, filenames in os.walk(rootDirectory):

		#check all files
		for filename in filenames:

			#make full
			# ->use realpath to resolve symlinks
			fullName = os.path.realpath(os.path.join(root, filename))

			#skip non-files (fifos etc....)
			if not os.path.isfile(fullName):

				#skip
				continue

			#only check executable files
			if os.access(fullName, os.X_OK):

				#save
				binaries.append(fullName)

	return binaries


#resolve paths that start with '@executable_path', or '@loader_path'
# ->note: since we are dealing only with main executables, both these resolve the same way
def resolvePath(binaryPath, unresolvedPath):

	#return var
	# ->init to what was passed in, since might not be able to resolve
	resolvedPath = unresolvedPath

	#resolve '@loader_path'
	if unresolvedPath.startswith('@loader_path'):

		#resolve
		resolvedPath = os.path.abspath(os.path.split(binaryPath)[0] + unresolvedPath.replace('@loader_path', ''))

	#resolve '@executable_path'
	elif unresolvedPath.startswith('@executable_path'):

		#resolve
		resolvedPath = os.path.abspath(os.path.split(binaryPath)[0] + unresolvedPath.replace('@executable_path', ''))

	return resolvedPath


#parse all binaries
# ->extract imports, etc
def parseBinaries(binaries):

	#dictionary of parsed binaries
	parsedBinaries = {}

	#scan all binaries
	for binary in binaries:

		#wrap
		try:

			#try load it (as mach-o)
			macho = macholib.MachO.MachO(binary)
			if not macho:

				#skip
				continue

		except:

			#skip
			continue

		#check if it's a supported (intel) architecture
		# ->also returns the supported mach-O header
		(isSupported, machoHeader) = isSupportedArchitecture(macho)
		if not isSupported:

			#skip
			continue

		#skip binaries that aren't main executables, dylibs or bundles
		if machoHeader.header.filetype not in [MH_EXECUTE, MH_DYLIB, MH_BUNDLE]:

			#skip
			continue

		#dbg msg
		#print ' scanning: %s' % binary

		#init dictionary for process
		parsedBinaries[binary] = {'LC_RPATHs': [], 'LC_LOAD_DYLIBs' : [], 'LC_LOAD_WEAK_DYLIBs': [] }

		#save type
		parsedBinaries[binary]['type'] = machoHeader.header.filetype

		#iterate over all load
		# ->save LC_RPATHs, LC_LOAD_DYLIBs, and LC_LOAD_WEAK_DYLIBs
		for loadCommand in machoHeader.commands:

			#handle LC_RPATH's
			# ->resolve and save
			if macholib.MachO.LC_RPATH == loadCommand[0].cmd:

				#grab rpath
				rPathDirectory = loadCommand[-1].rstrip('\0')

				#always attempt to resolve '@executable_path' and '@loader_path'
				rPathDirectory = resolvePath(binary, rPathDirectory)

				#save
				parsedBinaries[binary]['LC_RPATHs'].append(rPathDirectory)

			#handle LC_LOAD_DYLIB
			# ->save (as is)
			elif macholib.MachO.LC_LOAD_DYLIB == loadCommand[0].cmd:

				#tuple, last member is path to import
				importedDylib = loadCommand[-1].rstrip('\0')

				#save
				parsedBinaries[binary]['LC_LOAD_DYLIBs'].append(importedDylib)

			#handle for LC_LOAD_WEAK_DYLIB
			# ->resolve (except for '@rpaths') and save
			elif macholib.MachO.LC_LOAD_WEAK_DYLIB == loadCommand[0].cmd:

				#tuple, last member is path to import
				weakDylib = loadCommand[-1].rstrip('\0')

				#always attempt to resolve '@executable_path' and '@loader_path'
				weakDylib = resolvePath(binary, weakDylib)

				#save
				parsedBinaries[binary]['LC_LOAD_WEAK_DYLIBs'].append(weakDylib)

	return parsedBinaries


#process binaries
# ->find vulnerable thingz
def processBinaries(parsedBinaries):

	#results
	# ->list of dictionaries
	vulnerableBinaries = {'rpathExes': [], 'weakBins': []}

	#scan all parsed binaries
	for key in parsedBinaries:

		#grab binary entry
		binary = parsedBinaries[key]

		#STEP 1: check for vulnerable @rpath'd imports
		# note: only do this for main executables, since dylibs/bundles can share @rpath search dirs w/ main app, etc
		#       which we can't reliably resolve (i.e. this depends on the runtime/loadtime env)

		#check for primary @rpath'd import that doesn't exist
		if binary['type']== MH_EXECUTE and len(binary['LC_RPATHs']):

			#check all @rpath'd imports for the executable
			# ->if there is one that isn't found in a primary LC_RPATH, the executable is vulnerable :)
			for importedDylib in binary['LC_LOAD_DYLIBs']:

				#skip non-@rpath'd imports
				if not importedDylib.startswith('@rpath'):

					#skip
					continue

				#print 'has @rath\'d import: %s' % importedDylib

				#chop off '@rpath'
				importedDylib = importedDylib.replace('@rpath', '')

				#check the first rpath directory (from LC_RPATHs)
				# ->is the rpath'd import there!?
				if not os.path.exists(binary['LC_RPATHs'][0] + importedDylib):

					#not found
					# ->means this binary is vulnerable!
					vulnerableBinaries['rpathExes'].append({'binary': key, 'importedDylib': importedDylib, 'LC_RPATH': binary['LC_RPATHs'][0]})

					#bail
					break

		#STEP 2: check for vulnerable weak imports
		# can check all binary types...

		#check binary
		for weakDylib in binary['LC_LOAD_WEAK_DYLIBs']:

			#got to resolve weak @rpath'd imports before checking if they exist
			if weakDylib.startswith('@rpath'):

				#skip @rpath imports in dylibs and bundles, since they can share @rpath search dirs w/ main app, etc
				# which we can't reliably resolve (i.e. this depends on the runtime/loadtime env.)
				if binary['type'] != MH_EXECUTE:

					#skip
					continue

				#skip @rpath imports if binary doesn't have any LC_RPATHS
				if not len(binary['LC_RPATHs']):

					#skip
					continue

				#chop off '@rpath'
				weakDylib = weakDylib.replace('@rpath', '')

				#just need to check first LC_RPATH directory
				if not os.path.exists(binary['LC_RPATHs'][0] + weakDylib):

					#not found
					# ->means this binary is vulnerable!
					vulnerableBinaries['weakBins'].append({'binary': key, 'weakDylib': weakDylib, 'LC_RPATH': binary['LC_RPATHs'][0]})

					#bail
					break

			#path doesn't need to be resolved
			# ->check/save those that don't exist
			elif not os.path.exists(weakDylib):

				#not found
				# ->means this binary is vulnerable!
				vulnerableBinaries['weakBins'].append({'binary': key, 'weakBin': weakDylib})

				#bail
				break

	return vulnerableBinaries


if __name__ == '__main__':

	#dbg msg
	print '\nDYLIB HIJACK SCANNER (p. wardle)'
	print 'finds applications that may be vulnerable to dylib hijacking\n'

	#handle -h flag
	# ->print help/about msg
	if 2 == len(sys.argv) and '-h' == sys.argv[1]:

		#dbg msg(s)
		print ' no args:   will scan entire file system'
		print ' -l         will scan just loaded processes\n'

		#bail
		sys.exit(0)

	#check that env is compatible
	if not checkEnv():

		#bail
		sys.exit(-1)

	#check for -l flag
	# ->indicates scan of just loaded processes
	if 2 == len(sys.argv) and '-l' == sys.argv[1]:

		#dbg msg
		print 'getting list of loaded (running) processes...'

		#get list of loaded binaries
		binaries = loadedBinaries()

	#get list of *all* loaded files
	# ->this is default behavior
	else:

		#dbg msg
		print 'getting list of all process executables on system...'

		#get list of executable files on the file-system
		binaries = installedBinaries()

	#parse binares
	# ->extract LC_RPATHs, imports, etc
	parsedBinaries = parseBinaries(binaries)

	#process/scan em
	vulnerableBinaries = processBinaries(parsedBinaries)

	#display binaries that are vulnerable to rpath hijack
	if len(vulnerableBinaries['rpathExes']):

		#dbg msg
		print '\nfound %d binaries vulnerable to multiple rpaths:' % len(vulnerableBinaries['rpathExes'])

		#iterate over all and print
		for binary in vulnerableBinaries['rpathExes']:

			#dbg msg
			print '%s has multiple rpaths (%s)\n' % (binary['binary'], binary)

	#binary didn't have any
	else:

		#dbg msg
		print '\ndid not find any vulnerable to multiple rpaths'

	#display binaries that are vulnerable to weak import hijack
	if len(vulnerableBinaries['weakBins']):

			#dbg msg
			print '\nfound %d binaries vulnerable to weak dylibs:' % len(vulnerableBinaries['weakBins'])

			#iterate over all and print
			for binary in vulnerableBinaries['weakBins']:

				#dbg msg
				print '%s has weak import (%s)\n' % (binary['binary'], binary)

	#binary didn't have any
	else:

		#dbg msg
		print '\ndid not find any missing LC_LOAD_WEAK_DYLIBs'


	#dbg msg
	print '\nscan complete\n'