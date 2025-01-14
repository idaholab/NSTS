# Copyright 2024, Battelle Energy Alliance, LLC All Rights Reserved
#
# NVD2SSTIX
# Author: Taylor McCampbell
# Description: Give the program a search term or a cpe string and the program will create a stix bundle based on what the NVD returns when queried with those terms 

import requests, json, sys, os, pandas
from requests.auth import HTTPBasicAuth
from tqdm import tqdm
from stix2 import Vulnerability, Bundle, Relationship, Software, Identity, Note, Report
from urllib3.exceptions import InsecureRequestWarning
from datetime import datetime

#For the CWE functionality to work you must modify OpenCVE username and password in the fields below. Otherwise, there will be no CWEs added to your bundle
opencve_user = 'CHANGEME'
opencve_pass = 'CHANGEME'

# Pass NVD query the correct api endpoint for cpe searching
def cpe_search(cpe_string):
    cpeLink = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_string}'
    bundle = nvdQuery(cpeLink, cpe_string)
    return bundle

#Pass NVD query the correct api endpoint for term searching
def term_search(search_terms):
    #Base link without keywords
    nvd_link = f'https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch='
    
    #Building terms list
    terms = ''
    for term in search_terms:
        terms += f'{term} '
    
    termSearchLink = f'{nvd_link}{terms}'
    bundle = nvdQuery(termSearchLink, terms)
    return bundle

#Query the NVD and create objects with the proper link
def nvdQuery(searchLink, query):
    exploited_vulns = pandas.read_csv('known_exploited_vulnerabilities.csv', usecols=['cveID'])
    #Disables warning for using insecure ssl requests option (this is only necessary on the INL network and should be removed if using outside of the network)
    requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
    #Querying database
    print(f'Querying database with link: {searchLink}')
    try:
        response = requests.get(searchLink, verify = False)
    except Exception as e:
        print('NVD request failed')

    #Checking we got results from the search term
    try:
        results = json.loads(response.text)
    except Exception as e:
        print('Problem with converting request results to JSON')
        sys.exit(0)
    
    if results['totalResults'] == 0:
        print('No NVD results for the inputted search terms')
        sys.exit(0)
    print("Creating objects for each vulnerability")
    cve_list = []
    stix_objs = []
    previously_exploited = False
    try:
        for cve in tqdm(results['vulnerabilities']):
            #If the CVE has been exploited, set the val to true in the custom STIX property
            if cve['cve']['id'] in exploited_vulns.values:
                previously_exploited = True
            
            stix_objs.append(
                Vulnerability(
                name = cve['cve']['id'],
                description = cve['cve']['descriptions'][0]['value'],
                revoked = False,
                external_references = [{'source_name': 'MITRE', 'url': f'https://www.cve.org/CVERecord?id={cve["cve"]["id"]}'}],
                custom_properties={
                    "exploited": previously_exploited
                })
            )  
            target_reference = stix_objs[-1]['id']
            cve_list.append(stix_objs[-1]['id'])
            now = datetime.now()
            for report in cve['cve']['references']:
                    stix_objs.append(
                        Report(
                            name = report['source'],
                            report_types = ['vulnerability'],
                            external_references = [{'source_name': 'CVE Reference','url' : f'{report["url"]}'}],
                            object_refs=[target_reference],
                            published = now
                        )
                    )
                    stix_objs.append(
                        Relationship(
                            target_ref=target_reference,
                            source_ref=stix_objs[-1]['id'],
                            relationship_type='derived-from'
                        )
                    )
            #For every associated CWE, create a vulnerability STIX object. NOTE: This is not deduped yet
            try:
                for weakness in cve['cve']['weaknesses']:
                    if weakness['description'][0]['value'] == 'NVD-CWE-Other' or weakness['description'][0]['value'] == 'NVD-CWE-noinfo':
                        continue 
                    try:
                        weakness_req = requests.get(f"https://www.opencve.io/api/cwe/{weakness['description'][0]['value']}", auth = HTTPBasicAuth(opencve_user, opencve_pass), verify = False)
                        weakness_details = json.loads(weakness_req.text)
                    except Exception as e:
                        continue
                    stix_objs.append(
                        Vulnerability(
                            name = weakness_details['id'],
                            description = f'{weakness_details["name"]}: {weakness_details["description"]}',
                            revoked = False,
                            external_references = [{'description' : weakness['type'], 'source_name': weakness['source']}]
                        )
                    )
                    source_reference = stix_objs[-1]['id']
                    stix_objs.append(
                        Relationship(
                            source_ref = source_reference,
                            target_ref = target_reference,
                            relationship_type = 'related-to'
                        )
                    )
            except Exception as e:
                print(str(e))
                pass   
            #Getting vendor and software information from the CPE strings
            vendors = []
            software_objs = {}
            try:
                for configuration in cve['cve']['configurations']:
                    for node in configuration['nodes']:
                        for cpe_string in node['cpeMatch']:
                            vendor = cpe_string['criteria'].split(':')[3]
                            if vendor not in vendors:
                                vendors.append(vendor)
                                stix_objs.append(
                                    Identity(
                                        name = vendor,
                                    )
                                )
                                source_reference = stix_objs[-1]['id']
                                stix_objs.append(
                                    Relationship(
                                        source_ref=source_reference,
                                        target_ref= target_reference,
                                        relationship_type = 'related-to'
                                    )
                                )
                            software = cpe_string['criteria'].split(':')[4]
                            software_version = cpe_string['criteria'].split(':')[5]

                            if software in software_objs:
                                if software_version in software_objs[software]:
                                    continue
                                else:
                                    software_objs[software].append(software_version)
                                    stix_objs.append(
                                        Software(
                                            name = f'{software}',
                                            version = f'{software_version}'
                                        )
                                    )
                                    source_reference = stix_objs[-1]['id']
                                    stix_objs.append(
                                        Relationship(
                                        source_ref= source_reference,
                                        target_ref= target_reference,
                                        relationship_type='related-to'
                                        )
                                    )
                            else:
                                software_objs[software] = []
                                software_objs[software].append(software_version)
                                stix_objs.append(
                                    Software(
                                        name = f'{software}',
                                        version = f'{software_version}'
                                    )
                                )
                                source_reference = stix_objs[-1]['id']
                                stix_objs.append(
                                    Relationship(
                                        source_ref= source_reference,
                                        target_ref= target_reference,
                                        relationship_type='related-to'
                                    )
                                )
            except Exception as e:
                continue

        now = datetime.now()
        time  = now.strftime("%m/%d/%Y %H:%M:%S")
        note_obj = Note(
            content =  f"NVD queried on {time} using search terms OR cpe_string: {query}",
            object_refs = cve_list
        )
        stix_objs.append(note_obj)
        note_id = stix_objs[-1]['id']
        for obj in cve_list:
            stix_objs.append(
                Relationship(
                    source_ref=obj,
                    target_ref=note_id,
                    relationship_type='derived-from'
                )
            )
    except Exception as e:
        print(str(e))
        #print('No CVEs created')
    
    return stix_objs


def displayArgs():
    print('Usage:')
    print('\tUse a CPE string to query the NVD for CVEs')
    print('\t   python nvd2stix.py cpe <cpe_string> <output_file>')
    print()
    print('\tQuery the NVD using a custom search term')
    print('\t   python nvd2stix.py search <query query2 ...> <output_file>')
    print()
    print('\t   query: Search term to query the NVD (e.g. adobe acrobat reader)')
    print('\t   cpe_string: CPE string to be searched (e.g. cpe:2.3:a:ssh:ssh:1.2.6:*:*:*:*:*:*:*)')
    print('\t   output_file: STIX file containing created vulnerability objects (e.g. STIXOutput.json)')
    sys.exit(0)

if __name__=='__main__':
    try:
        sys.argv[1]
    except:
        print('Incorrect arguments')
        displayArgs()
        
    #CPE String search, rudimentary, only grabs CVEs
    if sys.argv[1] == 'cpe':
        objs = cpe_search(sys.argv[2])
        bundle = Bundle(objs, allow_custom=True)
        print("Writing Bundle")
        if os.path.isfile(sys.argv[3]): 
            with open(sys.argv[3], 'w') as output:
                output.write(bundle.serialize())
        else:
            with open(sys.argv[3], 'x') as output:
                output.write(bundle.serialize())
    #Search term, adds context with CWEs, product IDs, and note node displaying the date searched and terms used
    elif sys.argv[1] == 'search':
        terms = []
        for i in range(2, len(sys.argv) - 1):
            terms.append(sys.argv[i])
        stix_objs = term_search(terms)
        bundle = Bundle(stix_objs, allow_custom=True)
        print("Writing Bundle")
        if os.path.isfile(sys.argv[len(sys.argv) - 1]): 
            with open(sys.argv[len(sys.argv) - 1], 'w') as output:
                output.write(bundle.serialize())
        else:
            with open(sys.argv[len(sys.argv) - 1], 'x') as output:
                output.write(bundle.serialize())
    else:
        print('Incorrect arguments')
        displayArgs()