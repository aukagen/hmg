import requests, re 
import os
import sys
import subprocess

class runNmap:

	def __init__(self):
		self.command = ['sudo', 'nmap', '-sSV', '-O', '-oX', '/tmp/autoASMtoolOutput', '-p80,443']
		self.args = sys.argv #include they have to specify -iL targets.txt / single target + -p__ + -oX outputfile + full paths
		#self.default = ['-p80,443']
		'''this below code would get the filename output -> use to get outputfile for final results?
		try:
			self.outputFile = sys.argv[sys.argv.index('-oX') + 1]
		except:
			self.outputFile = self.default[2]
		'''	
		self.helpMenu = f'Either enter a single target or multiple by using the -iL flag and specifying the file with the targets. Dont forget to also specify the output file. Example:\npython run.py <outputFileName> -iL targets.txt\n'
		self.ready = False
		self.ipv4 = re.compile(r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}")
		self.domains = re.compile(r"(?=^.{4,253}$)(^((?!-)[a-zA-Z0-9-]{1,63}(?<!-)\.)+[a-zA-Z]{2,63}$)")
		if len(sys.argv) < 2:
			print(self.helpMenu)
		else:
			self.resultFile = sys.argv[1]

		
	def scan(self):
		'''
		Function which runs the nmap scan as a subprocess. User has the options of choosing whether they want to scan a single target or a list of targets, as well as name of output file.
		'''
		for i in sys.argv:
			if '-p' in i:
				self.command[6] = i
		if '-' in sys.argv[1]:
			print('Please enter the filename for the final output to be stored in as the first argument')
		elif '-default' in sys.argv:
			try:
				if '-iL' in sys.argv:
					try:
						self.command.append(sys.argv[sys.argv.index('-iL')])
						if os.path.exists(sys.argv[sys.argv.index('-iL')+1]):
							self.command.append(sys.argv[sys.argv.index('-iL')+1])
							self.ready = True
						else:
							print('The input file does not exist')
					except:
						print('Something went wrong, did you specify the target IP or list of targets using -iL?')
				elif (self.ipv4.match(sys.argv[3])) or (self.domains.match(sys.argv[3])):
					self.command.append(sys.argv[3])
					self.ready = True
				else:
					print('You need to specify a target')
			except:
				print('There was an error, check if you specified the targets correctly')	
			
		
		elif len(sys.argv) > 2:
			for i in sys.argv[2:]:
				if '-p' not in i:
					self.command.append(i)	
			self.ready = True
		else:
			return self.helpMenu

			
		if self.ready:
			print(f'Running scan and storing nmap scan results in /tmp/autoASMtoolOutput: \n')
			print(self.command)#remove this
			subprocess.run(self.command, stdout=open(os.devnull, 'wb'))
			print('Scan done\n')
		
		return self.ready
			
	def result(self):
		return self.resultFile
