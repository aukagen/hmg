import requests, re
from bs4 import BeautifulSoup


class raidNIST:
	def __init__(self):
		self.cves_list = []
		self.cves_mapped_to_severity = {}
		self.request_result_list = []
		
		self.cves_of_all_time = []
	def getCvesAndSevsFromFirstPage(self, cpe):
		'''
		Function will scan the NVD for the cve's of the found cpe on the first page only, as these will be the most recent and relevant. It will only return the CVEs rated CRITICAL in terms of severity. 
		'''
		try:
			cves = self.cves_list
			mapped = self.cves_mapped_to_severity
			tmp_list = self.request_result_list
			p = {
				'form_type':'Advanced', 
				'results_type':'overview', 
				'isCpeNameSearch':'true', 
				'seach_type':'all', 
				'query':cpe, 
				'startIndex':'0'
			}
			r = requests.get('https://nvd.nist.gov/vuln/search/results', params=p)
			soup = BeautifulSoup(r.content, 'html.parser')
			a = soup.find_all('a', attrs={'href':re.compile('CVE\-\d{4}\-\d{4,7}')})	
			for i in a:
				tmp_list.append(i.text)
			for c in range(len(tmp_list)-1):
				if 'CVE' in tmp_list[c]:
					cves.append(tmp_list[c])
					if 'CVE' not in tmp_list[c+1]:
						#if ('LOW' not in l[c+1]) and ('MEDIUM' not in l[c+1]):
						if ('LOW' not in tmp_list[c+1]) and ('MEDIUM' not in tmp_list[c+1]) and ('HIGH' not in tmp_list[c+1]):
							mapped[tmp_list[c]] = {'Severity':tmp_list[c+1]}
							c+=1
			return(mapped)
		except:
			return 'An error in retrieving CVEs'
	
	def getAllCvesForTrendingComp(self, cpe):
		'''
		This function will parse all the CVEs ofund for one CPE, and compare each one to the trending CVE's to see if there is a match. As opposed to the previous function in this class, it will scan the first 15 pages of CVE's taking into consideration older CVE's might be trending.
		'''
		try:
			tmp_all_cves = []
			index = 0
			for i in range(0, 301, 20):
				p = {
					'form_type':'Advanced', 
					'results_type':'overview', 
					'isCpeNameSearch':'true', 
					'seach_type':'all', 
					'query':cpe, 
					'startIndex':i
				}
				r = requests.get('https://nvd.nist.gov/vuln/search/results', params=p)
				soup = BeautifulSoup(r.content, 'html.parser')
				a = soup.find_all('a', attrs={'href':re.compile('CVE\-\d{4}\-\d{4,7}')})	
				for one in a:
					if 'CVE' in one.text:
						tmp_all_cves.append(one.text)	
			return tmp_all_cves
		except:
			return 'An error occured when retrieving CVEs to copmare wiht trending'	
