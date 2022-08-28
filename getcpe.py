import xml.etree.ElementTree as ET
import os

class getCPE:

	def __init__(self):
		self.file = '/tmp/autoASMtoolOutput'
		self.cpe_tag_name = 'cpe'
		self.cpe_list = []

	def fromFile(self):
		'''
		This function will parse the scan results file for the CPE's and store it in json format with the hosts they were linked to. 
		'''
		try:
			tree = ET.parse(self.file)
			dom = tree.getroot()
			scan_result = {}
			
			
			for hosts in dom.findall('host'):
				ensure_no_duplicates = []
				for address in hosts.findall('address'):
					continue
				for os in hosts.findall('os'):	
					osclass = []
					for osmatch in os.findall('osmatch'):
						for osc in osmatch.findall('osclass'):
							CPE = ''
							for CP in osc.findall('cpe'):
								ensure_no_duplicates.append(CP.text)
								CPE += CP.text
							if (ensure_no_duplicates.count(CPE) < 2):
								CPE2 = CPE.split(':')
								#filter out false positives
								if ('2.3' in CPE2[1] and len(CPE2) > 5) or ('2.3' not in CPE2[1] and ((len(CPE2) > 4) or ('/h' in CPE2[1]) or ('windows_' in CPE2[3]))):
									osclass.append({
										'CPE':CPE,
									})
						scan_result[address.get('addr')] = osclass
				for ports in hosts.findall('ports'):
					tmp = []
					for port in ports.findall('port'):
						for service in port.findall('service'):
							cpes = ''
							for cpe in service.findall('cpe'):
								cpes += CP.text
							tmp.append({'CPE':cpes})
					for the_cpes in tmp:
						for cpe_value in the_cpes['CPE']:
							if 'cpe' in cpe_value:
								scan_result[address.get('addr')].append(the_cpes)		
			return scan_result 
		except:	
			return 'File does not exist'
