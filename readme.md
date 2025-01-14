Copyright 2024, Battelle Energy Alliance, LLC All Rights Reserved

NVD2STIX generates a STIX bundle of vulnerabilities given a CPE string, a list of CPE strings within a text file, or a custom search query.

Usage:
	Use a CPE string to query the NVD for CVEs
    `python nvd2stix.py cpe <cpe_string> <output_file>`
	
	Query the NVD using a custom search term
    `python nvd2stix.py search <query query2 ...> <output_file>`

    query: Search term to query the NVD (e.g. adobe acrobat reader)
    cpe_string: CPE string to be searched (e.g. cpe:2.3:a:ssh:ssh:1.2.6:*:*:*:*:*:*:*)
    output_file: STIX file containing created vulnerability objects (e.g. STIXOutput.json)


LAST UPDATED: 7/16/2023 for CISA know exploited vulnerabilities listed! New vulnerabilities need to be added to the csv file
