import requests
import csv

# Base URL for the NVD CVE API
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_cve_data(query_parameters):
    """
    Fetches CVE data from the NVD API based on the provided parameters.
    
    :param query_parameters: Dictionary of query parameters for the API request.
    :return: JSON response from the API.
    """
    try:
        response = requests.get(BASE_URL, params=query_parameters)
        response.raise_for_status()  # Raise an exception for HTTP errors
        print(f"Successfully fetched data for parameters: {query_parameters}")
        return response.json()
    except requests.RequestException as e:
        print(f"Error fetching NVD data: {e}")
        return None

def save_cve_data_to_csv(cve_data, filename):
    """
    Saves CVE data to a single CSV file.
    
    :param cve_data: JSON data containing CVE details.
    :param filename: Name of the CSV file to save the data to.
    """
    if cve_data and 'vulnerabilities' in cve_data:
        with open(filename, 'a', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            for item in cve_data['vulnerabilities']:
                cve = item['cve']
                cve_id = cve['id']
                description = cve['descriptions'][0]['value'] if cve['descriptions'] else "N/A"
                published_date = cve.get('published', 'N/A')
                last_modified_date = cve.get('lastModified', 'N/A')
                writer.writerow([cve_id, description, published_date, last_modified_date])
                print(f"Saved CVE {cve_id} to {filename}")
    else:
        print("No vulnerabilities found or empty response.")

parameters_list = [
    {"cpeName": "", "resultsPerPage": 20, "startIndex": 0},
    {"cveId": ""},
    {"cvssV3Metrics": "", "resultsPerPage": 20, "startIndex": 0},
    {"cvssV3Severity": "", "resultsPerPage": 20, "startIndex": 0},
    {"cweId": "", "resultsPerPage": 20, "startIndex": 0},
    {"hasCertAlerts": "", "resultsPerPage": 20, "startIndex": 0},
    {"lastModStartDate": "", "lastModEndDate": "", "resultsPerPage": 20, "startIndex": 0},
    {"pubStartDate": "", "pubEndDate": "", "resultsPerPage": 20, "startIndex": 0}
]

# Name of the CSV file where all data will be saved
filename = "NIST_cve_data.csv"

# Write the header to the CSV file once
with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['CVE ID', 'Description', 'Published Date', 'Last Modified Date'])

# Fetch CVE data for each set of parameters and save to the CSV
for parameters in parameters_list:
    cve_data = get_cve_data(parameters)
    if cve_data:
        save_cve_data_to_csv(cve_data, filename)
        print(f"CVE data for parameters {parameters} saved to {filename}")
    else:
        print(f"No data fetched for parameters {parameters}")

print(f"All CVE data has been saved to {filename}")

