import requests
from bs4 import BeautifulSoup
import pandas as pd
import os

def scrape_nvd(start_index):
    url = f"https://nvd.nist.gov/vuln/search/results?isCpeNameSearch=false&results_type=overview&form_type=Advanced&search_type=all&startIndex={start_index}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.content
    else:
        return None
    
def extract_data(html_content):
    """
    Extracts vulnerability data from the HTML content.

    Args:
        html_content (bytes): The HTML content of the page.

    Returns:
        tuple: A tuple containing the headers (list) and rows (list) of the extracted data.
    """
    soup = BeautifulSoup(html_content, 'html.parser')
    table = soup.find('table', class_='table table-striped table-hover')
    headers = [th.text.strip() for th in table.find('thead').find_all('th')]
    headers = [header.replace('CVSS Severity', 'Published Date') for header in headers] # Replace 'CVSS Severity' with 'Published Date'
    headers.append("CVSS Severity")
    headers.append("Link")
    # header = ['Vuln ID', 'Summary', 'Published Date', 'CVSS Severity', 'Link']
    # Extract data from the table

    rows = []
    for row in table.find('tbody').find_all('tr'):

        # Vulnerability ID is in the first column
        vul_id = row.find('a').text.strip()
        summary = "".join(row.find('p').text.strip('\n').split('\n'))

        published = row.find('td').find_all('span')[0].text.strip()

        # CVSS Severity is in the second column
        cvss_severity = row.find_all('td')[1].text.strip()
        # CVSS Severity link
        if row.find_all('td')[1].find('a') is not None:
            cvss_info = "https://nvd.nist.gov" + row.find_all('td')[1].find('a')['href']
        else:
            cvss_info = None
        cvss_severity = cvss_severity + " (" + str(cvss_info) + ")"

        link = ("https://nvd.nist.gov"+row.find('a')['href'])

        rows.append([vul_id, summary, published, cvss_severity, link])
    return headers, rows

def save_to_csv(headers, rows):
    """
    Saves the extracted vulnerability data to CSV files.

    Args:
        headers (list): The headers of the data.
        rows (list): The rows of the data.
    """
    for row in rows:
        year = row[0].split('-')[1]
        file_path = os.path.join('Data', 'NVD', f'CVE_{year}.csv')

        if not os.path.exists(file_path):
            df = pd.DataFrame(columns=headers)
            df.to_csv(file_path, sep='|' , index=False)
        else:
            df = pd.read_csv(file_path, sep="|" , engine='python')
            # Ensure column names are consistent
            if list(df.columns) != headers:
                continue  # Skip this row if column names are inconsistent

        # Check if the vulnerability ID already exists in the CSV
        if row[0] not in df['Vuln ID'].values:
            # Append the new row to the DataFrame
            new_row = pd.DataFrame([row], columns=headers)
            df = pd.concat([df, new_row], ignore_index=True)
            df.sort_values(by='Vuln ID', inplace=True)
            # Updated to overwrite the entire file
            df.to_csv(file_path, sep='|', index=False)


if __name__ == "__main__":
    for start_index in range(0, 101, 20):  # Loop until 100 with step size of 20
        html_content = scrape_nvd(start_index)
        if html_content is None:
            print("Failed to retrieve data.")
            break
        headers, rows = extract_data(html_content)
        if not rows:
            print("No more data to scrape.")
            break
        save_to_csv(headers, rows)
        print(f"Scraped and saved data from page {start_index // 20 + 1}")
