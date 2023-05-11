import requests
import argparse
from dotenv import load_dotenv
import os
import csv

# Charger les variables d'environnement depuis le fichier .env
load_dotenv()

def get_active_cve(os_name, severity, count, api_key):
    base_url = 'https://services.nvd.nist.gov/rest/json/cves/1.0'
    query_url = f"{base_url}?keyword={os_name}&isExactMatch=true&resultsPerPage={count}&api_key={api_key}"

    try:
        response = requests.get(query_url)
        response.raise_for_status()
        cve_data = response.json()

        if 'result' in cve_data:
            cve_list = []
            for result in cve_data['result']['CVE_Items']:
                cve_id = result['cve']['CVE_data_meta']['ID']
                description = result['cve']['description']['description_data'][0]['value']
                cve_severity = get_cve_severity(result)
                cvss_score = get_cvss_score(result)
                cve_link = get_cve_link(result)
                if cve_severity == severity or severity == 'all':
                    cve_list.append({'CVE ID': cve_id, 'Description': description, 'Severity': cve_severity, 'CVSS Score': cvss_score, 'CVE Link': cve_link})

            if cve_list:
                if output_format == 'csv':
                    save_to_csv(cve_list, output_file)
                else:
                    for cve in cve_list:
                        print(f"CVE ID: {cve['CVE ID']}")
                        print(f"Description: {cve['Description']}")
                        print(f"Severity: {cve['Severity']}")
                        print(f"CVSS Score: {cve['CVSS Score']}")
                        print(f"CVE Link: {cve['CVE Link']}")
                        print('---')
            else:
                print("No active CVEs found for the specified OS.")

    except requests.exceptions.RequestException as e:
        print(f"Error: {e}")

def get_cve_severity(cve_item):
    if 'baseMetricV3' in cve_item['impact']:
        return cve_item['impact']['baseMetricV3']['cvssV3']['baseSeverity']
    elif 'baseMetricV2' in cve_item['impact']:
        return cve_item['impact']['baseMetricV2']['severity']
    else:
        return 'Unknown'

def get_cvss_score(cve_item):
    if 'baseMetricV3' in cve_item['impact']:
        return cve_item['impact']['baseMetricV3']['cvssV3']['baseScore']
    elif 'baseMetricV2' in cve_item['impact']:
        return cve_item['impact']['baseMetricV2']['cvssV2']['baseScore']
    else:
        return 'Unknown'

def get_cve_link(cve_item):
    return f"https://nvd.nist.gov/vuln/detail/{cve_item['cve']['CVE_data_meta']['ID']}"

def save_to_csv(cve_list, output_file):
    keys = cve_list[0].keys()

    with open(output_file, 'w', newline='') as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=keys)
        writer.writeheader()
        writer.writerows(cve_list)

# Analyse des arguments de ligne de commande
parser = argparse.ArgumentParser(description='Find active CVEs for an OS.')
parser.add_argument('os_name', help='Name of the target OS')
parser.add_argument('severity', help='Desired severity level (low, medium, high, critical, all)')
parser.add_argument('--count', type=int, default=10, help='Number of active vulnerabilities to display (default: 10)')
parser.add_argument('--output', dest='output_file', help='Output file (CSV)')
args = parser.parse_args()

output_file = args.output_file
output_format = 'console' if output_file is None else 'csv'

# Récupérer la clé d'API à partir de l'environnement
api_key = os.getenv('API_KEY')

if api_key is None:
    print("API_KEY not found in the environment. Make sure it is defined in the .env file.")
else:
    # Utilisation des arguments et de la clé d'API pour récupérer les CVEs actives
    get_active_cve(args.os_name, args.severity, args.count, api_key)
