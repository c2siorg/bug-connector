# Bug Connector

## Introduction:

The idea of this project is to create a public dataset based on openly available CVE information, the key goal is to create fully functional scapers set to gather CVE information from different sources augment comprehensive data points, and make it publicly available for research purposes.
 
## Project Structure:    
- The project is divided into 3 main components:
  - Data Collection
  - Data Processing
  - Data Storage
- Each component is further divided into sub-components, and each sub-component is a standalone module that can be used independently.

## Data Collection:
- The data collection component is responsible for gathering CVE information from different sources, the sources can be:
    - [NVD](https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false)
    - [MITRE](https://www.cve.org/Downloads#current-format)
    - [CVE Details](https://www.cvedetails.com/vulnerability-search.php?f=1&vendor=&product=&cweid=&cvssscoremin=&cvssscoremax=&publishdatestart=&publishdateend=&updatedatestart=&updatedateend=&cisaaddstart=&cisaaddend=&cisaduestart=&cisadueend=&page=1)
    - [Rapid7](https://www.rapid7.com/db/?q=&type=nexpose)
- Each source has its own module, which is responsible for gathering and storing data from the source in a format.
  
  **Alternative:**
  - [CvelistV5](https://github.com/CVEProject/cvelistV5) is a public repository that contains a list of all CVEs, and the data is updated regularly, the data is available in JSON format, and the data can be used for research purposes.
  
## Data Processing:
- The data processing component is responsible for processing the data collected from different sources, the processing can be:
    - Data Augmentation
    - Data Normalization
    - Data Enrichment
- Each processing module is responsible for processing and storing the data in a predefined format.

## Data Storage:
- The data storage component is responsible for storing the processed data in a predefined format, the storage can be:
    - CSV
    - JSON
    - XML
    - SQL
- Each storage module is responsible for storing the data in a predefined format.

## Data Updation:
- The data updation component is responsible for updating the data regularly, the update can be:
    - Daily
    - Weekly
    - Monthly
- Using Github Actions, the data can be updated regularly, and the data can be made publicly available for research purposes.

## Deployment:
- The project is deployed on a [Streamlit](https://streamlit.io) platform, and the data is publicly available for research purposes.

## Conclusion:
- The project is a fully functional public dataset based on openly available CVE information, the project is divided into 3 main components, and each component is further divided into sub-components, and each sub-component is a standalone module that can be used independently.

