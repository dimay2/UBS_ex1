#libraries import
import requests
import pandas as pd
import json
from datetime import date, datetime, timedelta
import urllib.parse
import csv
import logging

#======== load settings from file =======
settings_file=open("settings")
settings_data=json.load(settings_file)
settings_file.close()

#global params definition
url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"
payload = {}
headers= {}

#global params initialization from "settings" (json) file
v_virtualMatchString=settings_data['v_virtualMatchString']
start_date=settings_data['start_date']
end_date=settings_data['end_date']

# Open CSV file in write mode
file = open('cve_out.csv', 'w', newline='')
# Create a CSV writer object pointer
csv_writer = csv.writer(file)
output_str=['CVE ID', 'Vulnerability Name', 'CVSS Base Score', ' Vulnerability Description', 'Exploited (Tags)']
csv_writer.writerow(output_str)

#logging
log_file=open("general.log",mode="w")
logging.basicConfig(filename='general.log', level=logging.INFO)

# ==== API call function - get CVE list====
def cve_api_func(v_pubStartDate, v_pubEndDate):
    global url
    global payload
    global headers

    params = {'pubStartDate' : str(v_pubStartDate), 'pubEndDate' : str(v_pubEndDate), 'virtualMatchString' : v_virtualMatchString, 'hasKev':''}
    #params = {'pubStartDate' : str(v_pubStartDate), 'pubEndDate' : str(v_pubEndDate), 'hasKev':''}
    params_period_str = urllib.parse.urlencode(params, safe=':')
    try:
        response = requests.request("GET", url, headers=headers, data = payload, params=params_period_str)
        if response.status_code == 200:
            myjson = response.json()
            #print(response.url)
            logging.info('API call URL - %s' %(response.url))
            
            for cve_item in myjson['vulnerabilities']:
                tags = []
                cve_id=str(cve_item['cve']['id'])
                cisaVulnerabilityName=str(cve_item['cve']['cisaVulnerabilityName'])
                #print(cve_id)
                logging.info('CVE ID - %s' %(cve_id))
                for metric_item in cve_item['cve']['metrics']:
                    #print(metric_item)
                    if metric_item == 'cvssMetricV31':
                        baseScore=str(cve_item['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore'])
                        break
                    elif metric_item == 'cvssMetricV2':
                        baseScore=str(cve_item['cve']['metrics']['cvssMetricV2'][0]['cvssData']['baseScore'])
                for description_item in cve_item['cve']['descriptions']:
                    if description_item['lang']=='en':
                        description=str(description_item['value'])
                        break
                for ref_item in cve_item['cve']['references']:
                    #print(ref_item)
                    if 'tags' in ref_item:
                        for tag_item in ref_item['tags']:
                            tags.append(tag_item)
                    else:
                        #print('Error tags parse: no tags found')
                        logging.warning('No tags found for CVE ID=%s' %cve_id)
                tags_unique_str=str(set(tags))
                cve_api_results_lst=[cve_id, cisaVulnerabilityName, baseScore, description, tags_unique_str]
                # write output to CSV file
                csv_writer.writerow(cve_api_results_lst)
        else:
            print("CVE API call error code =",response.status_code)
    except requests.exceptions.RequestException as e:
        logging.error('CVE API call error: '+ str(e))
        raise SystemExit(e)
# ==== END - API call function ====

# ====== MAIN function ==========
def main():
    global url

    #API call to CVE
    a= datetime
    d1 = datetime.strptime(start_date, "%Y-%m-%d")
    period_start=d1
    d2 = datetime.strptime(end_date, "%Y-%m-%d")
    period_end=d2
    days_delta = d2 - d1
    # CVE REST API call loop for <=120d iterations until whole period covered
    while True:
        if days_delta.days < 120:
            v_pubStartDate = period_start.strftime('%Y-%m-%d') + str("T00:00:00.000")
            v_pubEndDate = d2.strftime('%Y-%m-%d') + str("T23:59:59.999")
            cve_api_func(v_pubStartDate, v_pubEndDate)
            break
        else:
            period_end = period_start + timedelta(days=119)
            v_pubStartDate = period_start.strftime('%Y-%m-%d') + 'T00:00:00.000'
            v_pubEndDate = period_end.strftime('%Y-%m-%d') + 'T23:59:59.999'
            cve_api_func(v_pubStartDate, v_pubEndDate)
            period_start = period_end
            days_delta = d2 - period_start
    
    # Close the file
    file.close()
    log_file.close()

#======= MAIN execution =======
if __name__ == "__main__":
    main()