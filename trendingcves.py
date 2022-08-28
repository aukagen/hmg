import requests, re

class CveTrends():
	
	def __init__(self):
		self.url = 'https://cvetrends.com/api/cves/24hrs'
		self.trending_cves = []
		
	def getTrendingCves(self):
		'''
		This function will scrape the cvetrends website. The result will be compared to the CVEs found for each cpe and if a match is found this will be highlighted in the final output to be followed up on.
		'''
		try:
			r = requests.get(self.url)
			a = re.findall('CVE\-\d{4}\-\d{4,7}', r.text)
			for one in a:
				if one not in self.trending_cves:
					self.trending_cves.append(one)
			return self.trending_cves
		except:
			return 'An error occured when retrieving trending CVEs'	
