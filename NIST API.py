import requests

# Base URL for the NVD CVE API
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_cve_data(parameters):
    """
    Fetches CVE data from the NVD API based on the provided parameters.

    :param parameters: Dictionary of query parameters for the API request.
    :return: JSON response from the API.
    """
    response = requests.get(BASE_URL, params=parameters)
    response.raise_for_status()  # Raise an exception for HTTP errors
    return response.json()


parameters = {
    "cpeName": "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
    "resultsPerPage": 20,
    "startIndex": 0
}

# Fetch and print CVE data
cve_data = get_cve_data(parameters)
print(cve_data)


parameters = {
    "cveId": "CVE-2019-1010218"
}

# Fetch and print CVE data
cve_data = get_cve_data(parameters)
print(cve_data)


parameters = {
    "cvssV3Metrics": "AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:L/A:L",
    "resultsPerPage": 20,
    "startIndex": 0
}

# Fetch and print CVE data
cve_data = get_cve_data(parameters)
print(cve_data)


parameters = {
    "cvssV3Severity": "LOW",
    "resultsPerPage": 20,
    "startIndex": 0
}

# Fetch and print CVE data
cve_data = get_cve_data(parameters)
print(cve_data)


parameters = {
    "cweId": "CWE-287",
    "resultsPerPage": 20,
    "startIndex": 0
}

# Fetch and print CVE data
cve_data = get_cve_data(parameters)
print(cve_data)


parameters = {
    "hasCertAlerts": "",
    "resultsPerPage": 20,
    "startIndex": 0
}

# Fetch and print CVE data
cve_data = get_cve_data(parameters)
print(cve_data)


parameters = {
    "lastModStartDate": "2021-08-04T00:00:00.000",
    "lastModEndDate": "2021-10-22T00:00:00.000",
    "resultsPerPage": 20,
    "startIndex": 0
}

# Fetch and print CVE data
cve_data = get_cve_data(parameters)
print(cve_data)


parameters = {
    "pubStartDate": "2021-08-04T00:00:00.000",
    "pubEndDate": "2021-10-22T00:00:00.000",
    "resultsPerPage": 20,
    "startIndex": 0
}

# Fetch and print CVE data
cve_data = get_cve_data(parameters)
print(cve_data)
