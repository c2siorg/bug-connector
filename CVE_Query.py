import pandas as pd
from sentence_transformers import SentenceTransformer, util  # For semantic similarity
import ssl
import urllib3

# SSL Issue Handling: Disable SSL certificate verification
ssl._create_default_https_context = ssl._create_unverified_context
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to load CSV and handle errors
def load_csv(file_path, skip_rows=None):
    try:
        if skip_rows:
            df = pd.read_csv(file_path, encoding='latin1', on_bad_lines='skip', skiprows=skip_rows)  # Skip bad lines and rows
        else:
            df = pd.read_csv(file_path, encoding='latin1', on_bad_lines='skip')  # Skip bad lines
        print(f"Successfully loaded {file_path}")
        print(f"Columns in {file_path}: {df.columns.tolist()}")  # Print column names for debugging
        return df
    except pd.errors.ParserError as e:
        print(f"Error loading CSV file at {file_path}: {e}")
        return pd.DataFrame()  # Return an empty DataFrame if there's an error
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return pd.DataFrame()  # Return an empty DataFrame if any other error occurs

# Function to extract commit descriptions from 'title/message'
def extract_commit_data(commit_df):
    commit_df['CVE_ID'] = commit_df['title/message'].str.extract(r'(CVE-\d{4}-\d+)')  # Extract CVE ID
    commit_df['Commit_Message'] = commit_df['title/message'].apply(lambda x: x.split(': ', 1)[-1] if ': ' in x else x)  # Extract the description or keep the full message
    return commit_df

# Function to map CVEs to commit messages using semantic similarity
def map_cves_to_commits(cve_df, commit_df, model, threshold=0.5):
    cve_descriptions = cve_df['Description'].tolist()
    commit_messages = commit_df['Commit_Message'].tolist()

    print("Encoding commit messages and CVE descriptions...")
    commit_embeddings = model.encode(commit_messages, convert_to_tensor=True)
    cve_embeddings = model.encode(cve_descriptions, convert_to_tensor=True)

    print(f"Number of CVE embeddings: {len(cve_embeddings)}")
    print(f"Number of commit embeddings: {len(commit_embeddings)}")

    mapped_data = []

    try:
        print("Computing cosine similarities between commits and CVEs...")
        cosine_scores = util.cos_sim(cve_embeddings, commit_embeddings)
        print("Similarity computation completed.")
    except Exception as e:
        print(f"Error during similarity computation: {e}")
        return pd.DataFrame()  # Return an empty DataFrame if an error occurs

    print("Analyzing mappings...")
    for cve_idx in range(len(cve_df)):
        cve_row = cve_df.iloc[cve_idx]
        cve_id = cve_row.get('Name', '')  # From MITRE data
        cve_description = cve_row.get('Description', '')

        # Removed the tensor scores print statement
        scores = cosine_scores[cve_idx]

        for commit_idx, score in enumerate(scores):
            if score >= threshold:
                commit_row = commit_df.iloc[commit_idx]
                commit_message = commit_row.get('Commit_Message', '')

                # Print each mapping being added
                print(f"Mapping: CVE_ID={cve_id}, Commit_Message={commit_message}, Similarity_Score={score.item()}")

                mapped_data.append({
                    'CVE_ID': cve_id,  # From MITRE data
                    'Commit_Message': commit_message,
                    'Similarity_Score': score.item(),  # Cosine similarity score
                })

    # Convert the list of mappings to a DataFrame
    mapped_df = pd.DataFrame(mapped_data)

    # Set pandas options to display the entire content of each column
    pd.set_option('display.max_colwidth', None)  # Show the full content of each column

    return mapped_df

# Function to search for a specific CVE ID in both MITRE and NIST datasets
def search_cve(cve_id, mitre_df, nist_df, commit_df, model, threshold=0.5):
    # Search for the CVE ID in the MITRE dataset
    mitre_cve_data = mitre_df[mitre_df['Name'] == cve_id]

    # Search for the CVE ID in the NIST dataset
    nist_cve_data = nist_df[nist_df['CVE ID'] == cve_id]

    # Combine data from MITRE and NIST if any matches were found
    combined_cve_data = pd.concat([mitre_cve_data, nist_cve_data])

    if combined_cve_data.empty:
        print(f"CVE ID {cve_id} not found in MITRE or NIST datasets.")
        return pd.DataFrame()

    # Map the found CVE description to Apache commit data
    mapped_df = map_cves_to_commits(combined_cve_data, commit_df, model, threshold)

    if mapped_df.empty:
        print(f"No mappings found for CVE ID {cve_id}.")
    else:
        print(f"Mappings for CVE ID {cve_id}:")
        print(mapped_df)

    return mapped_df

# Main execution
if __name__ == "__main__":
    model = SentenceTransformer('paraphrase-MiniLM-L6-v2')  # Lightweight and efficient model

    # File paths for the MITRE, NIST, and Apache datasets
    mitre_file_path = r'C:\Users\ADMIN\Desktop\bug-connector\mitre_allitems.csv'
    nist_file_path = r'C:\Users\ADMIN\Desktop\bug-connector\NIST_cve_data.csv'
    commit_file_path = r'C:\Users\ADMIN\Desktop\bug-connector\Apache_cve_data.csv'

    # Load the MITRE CSV with skiprows (column headers on line 3)
    mitre_df = load_csv(mitre_file_path, skip_rows=2)  # Skips the first two rows
    # Load the NIST CSV normally (assuming headers are in the first row)
    nist_df = load_csv(nist_file_path)
    # Load the Apache commit data CSV
    commit_df = load_csv(commit_file_path)

    # Extract commit messages from Apache commit data
    commit_df = extract_commit_data(commit_df)

    # Example: Search for a specific CVE ID (user input)
    cve_id = input("Enter the CVE ID to search for (e.g., CVE-2023-12345): ")

    # Search for the CVE ID in both MITRE and NIST datasets and map to Apache commits
    search_cve(cve_id, mitre_df, nist_df, commit_df, model)
