# bug-connector
The idea of this project is to create a public dataset based on openly available CVE information, the key goal is to create fully functional scapers set to gather CVE information from different sources augment comprehensive data points, and make it public


## Project Overview
This project provides a system that maps Common Vulnerabilities and Exposures (CVE) data from public sources (like MITRE and NIST) to historical commit data from the Apache repository. The system uses natural language processing (NLP) models, specifically SentenceTransformers, to generate semantic embeddings of text and computes cosine similarity to identify the most relevant commits for each CVE. This allows developers and security researchers to link vulnerabilities to specific code changes, making it easier to track the resolution of security issues in open-source software.

The project is designed as a command-line interface (CLI) tool for ease of use, allowing users to query specific CVEs, view relevant commit messages, and output the results to a file. The system also supports processing large datasets from MITRE and NIST to maintain up-to-date vulnerability mappings.

## Features
- Load CVE data from MITRE and NIST sources.
- Map CVEs to commits using semantic similarity.
- Query-specific CVEs through the CLI.

## Installation Guide
This guide walks you through setting up the project for CVE to Apache Commit Mapping.

1. Prerequisites
Before setting up the project, ensure that the following dependencies are installed on your system:
-Python 3.7 or later: This project requires Python, which you can download from here.
-pip: Ensure you have pip installed to manage Python packages.

2. Clone the Repository
First, clone the GitHub repository to your local machine:

```bash
git clone https://github.com/yourusername/bug-connector.git
cd bug-connector
```
3. Create a Virtual Environment (Optional)
It is highly recommended to use a virtual environment to manage dependencies and avoid conflicts.

To create and activate a virtual environment:

```bash
# Create virtual environment
python -m venv venv
```

# Activate the virtual environment
# On Windows
```venv\Scripts\activate```

# On MacOS/Linux
```source venv/bin/activate```

4. Install Dependencies
   
Install the required Python packages using pip:
```bash
pip install -r requirements.txt
```

5. Running the CLI
   
To run the main command-line interface (CLI):

```bash
python cli.py --output_file "filepath\bug-connector\results_mapped_cve.csv"

```
You will be prompted to enter a CVE ID, and the system will output the mapped CVE-commit information to the specified CSV file (output.csv).

## Contributing

Feel free to open issues or submit pull requests. Ensure you adhere to the project's coding standards and provide appropriate documentation for any new features or fixes.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For any inquiries or support, please contact joy.zawadi32@gmail.com
