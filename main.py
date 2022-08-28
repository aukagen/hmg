import json
import time
import termcolor
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.common.by import By
from getcpe import getCPE
from nmapscan import runNmap
from raidnist import raidNIST
from trendingcves import CveTrends

if __name__ == "__main__":
	runScan = runNmap().scan() # this will output the result to the output file
	
	if runScan == True:
		trending_ones = []
		list_of_target_cpes = getCPE().fromFile() 
		cpe_cve_sev = {} # this will be populated with all the most recent CVEs taken from the first page of NVD
		trending_cves_match = {} # this will be populated with ALL cve's from the API to be compared with trending CVE's as old ones can trend unexpectedly
		trending_cves = CveTrends().getTrendingCves()

		
		#Selenium driver setup: 
		url = 'https://www.exploit-db.com/search?cve='
		options = Options()
		options.add_argument("--headless")
		driver = webdriver.Firefox(options=options)
		
		print('CPEs have been retrieved, moving on to CVEs and exploits')
		try:
			#Below code bit gets all CVEs and their severities from NVD
			for host in list_of_target_cpes:
				for mapping in list_of_target_cpes[host]:
					cpe_cve_sev[mapping['CPE']] = raidNIST().getCvesAndSevsFromFirstPage(mapping['CPE'])
					
			
			# below code gets each of the cpe's in the original dicitonary
			for hosts in list_of_target_cpes:
				for each in range(len(list_of_target_cpes[hosts])):
					CPE = list_of_target_cpes[hosts][each]['CPE']
					for i in cpe_cve_sev:
						if (i in CPE) and (len(cpe_cve_sev[i]) > 0): #was 1 previously?
							list_of_target_cpes[hosts][each]['CVEs'] = cpe_cve_sev[i]
					if 'CVEs' in list_of_target_cpes[hosts][each].keys():
						li = list(list_of_target_cpes[hosts][each]['CVEs'].keys())
						for cve in li:
							other_dict = {}
							exploits = {}
							print(f'\nRetrieving exploits for: {cve}..')
							mod_cve = cve.replace('CVE-','')
							driver.get(f"{url}{mod_cve}")
							time.sleep(5)
							table = driver.find_element(by=By.XPATH, value='//table[@id="exploits-table"]/tbody')
							l = list((table.text).split('\n'))
							if (len(l) == 0):
								print('no data will be retrieved')
							elif ('No data available in table' in l) or ('' in l):
								print('No exploits found \n')
							elif (len(l) == 1) and ('No data available in table' not in l):
								exploits[driver.find_element(by=By.XPATH, value='//table[@id="exploits-table"]/tbody/tr[1]/td[5]').text] = driver.find_element(by=By.XPATH, value=f'//table[@id="exploits-table"]/tbody/tr[1]/td[5]/a').get_attribute('href')
							elif (len(l) > 1):
								for i in range(1,len(l)):
									exploits[driver.find_element(by=By.XPATH, value=f'//table[@id="exploits-table"]/tbody/tr[{i}]/td[5]').text] = driver.find_element(by=By.XPATH, value=f'//table[@id="exploits-table"]/tbody/tr[{i}]/td[5]/a').get_attribute('href')
							if len(exploits) > 0:
								list_of_target_cpes[hosts][each]['CVEs'][cve]['Exploits'] = exploits 
					all_cves_for_trending = raidNIST().getAllCvesForTrendingComp(CPE) 
					for key in all_cves_for_trending:
						for tre in trending_cves:
							if key == tre:
								string = f'A trending CVE '+termcolor.colored(key, 'red', attrs=['blink'])+f' was found for target "{hosts}". It is linked to {list_of_target_cpes[hosts][each]["CPE"]}.\n'
								trending_ones.append(string)
					

							
			#close selenium driver
			driver.quit()
			
			# result to file
			try:
				resultFile = runNmap().result()
				print(termcolor.colored(f'Storing the final results to {resultFile}', 'cyan'))
				if 'json' not in resultFile:
					resultFile += '.json'
				with open(resultFile, 'w') as f:			
					f.write('Trending CVE matches found: \n')
					for trending in trending_ones:
						f.write(trending)
					f.write('\n')
					f.write(json.dumps(list_of_target_cpes, sort_keys=False, indent=3))
			except:
				print('File to write results to might not exist or was not specified')
				
			# printing final results
			print(termcolor.colored('########## TRENDING CVES: ##########', 'green'), '\n')
			if len(trending_ones) == 0:
				print('No trending CVEs found', '\n\n\n')
			for trending in trending_ones:	
				print(trending, '\n\n')
			print(termcolor.colored('########## FULL LIST OF CVES AND THEIR SEVERITY PER TARGET ##########', 'green'), '\n')
			print(json.dumps(list_of_target_cpes, sort_keys=False, indent=4))
			
			
			
		except:
			print('Something went wrong. Check your arguments and make sure you have used the right ones. Also check your internet connection.')
	else:
		print('Check your arguments and rerun the tool')
