import pandas as pd
from sentence_transformers import SentenceTransformer, util
import argparse

# Define constants for file paths
MITRE_FILE_PATH = 'mitre_allitems.csv'
NIST_FILE_PATH = 'NIST_cve_data.csv'
COMMIT_FILE_PATH = 'Mapped_CVE_file.csv'

# Function to load CSV and handle errors
def load_csv(file_path, skip_rows=None):
    try:
        if skip_rows:
            df = pd.read_csv(file_path, encoding='latin1', on_bad_lines='skip', skiprows=skip_rows)
        else:
            df = pd.read_csv(file_path, encoding='latin1', on_bad_lines='skip')
        print(f"Successfully loaded {file_path}")
        print(f"Columns in {file_path}: {df.columns.tolist()}")
        return df
    except pd.errors.ParserError as e:
        print(f"Error loading CSV file at {file_path}: {e}")
        return pd.DataFrame()
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        return pd.DataFrame()

# Function to extract commit descriptions from 'title/message'
def extract_commit_data(commit_df):
    if 'CVE_ID' not in commit_df.columns:
        commit_df['CVE_ID'] = commit_df['CVE_ID'].str.extract(r'(CVE-\d{4}-\d+)')
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
        return pd.DataFrame()

    print("Analyzing mappings...")
    for cve_idx in range(len(cve_df)):
        cve_row = cve_df.iloc[cve_idx]
        cve_id = cve_row.get('CVE ID', '')
        cve_description = cve_row.get('Description', '')

        scores = cosine_scores[cve_idx]

        for commit_idx, score in enumerate(scores):
            if score >= threshold:
                commit_row = commit_df.iloc[commit_idx]
                commit_message = commit_row.get('Commit_Message', '')

                mapped_data.append({
                    'CVE_ID': cve_id,
                    'Commit_Message': commit_message,
                    'Similarity_Score': score.item(),
                })

    return pd.DataFrame(mapped_data)

# Function to search for a specific CVE ID in both MITRE and NIST datasets
def search_cve(cve_id, mitre_df, nist_df, commit_df, model, threshold=0.5):
    mitre_cve_data = mitre_df[mitre_df['Name'] == cve_id]
    nist_cve_data = nist_df[nist_df['CVE ID'] == cve_id]

    combined_cve_data = pd.concat([mitre_cve_data, nist_cve_data])

    if combined_cve_data.empty:
        print(f"CVE ID {cve_id} not found in MITRE or NIST datasets.")
        return pd.DataFrame()

    mapped_df = map_cves_to_commits(combined_cve_data, commit_df, model, threshold)

    return mapped_df

# Main function for the CLI
def main():
    parser = argparse.ArgumentParser(description="CVE and Commit Mapping CLI")
    parser.add_argument('--output_file', type=str, help="Output file for mapped data", required=True)

    args = parser.parse_args()

    model = SentenceTransformer('paraphrase-MiniLM-L6-v2')

    mitre_df = load_csv(MITRE_FILE_PATH, skip_rows=2)
    nist_df = load_csv(NIST_FILE_PATH)
    commit_df = load_csv(COMMIT_FILE_PATH)
    commit_df = extract_commit_data(commit_df)

    # Prompt user for CVE ID
    cve_id = input("Enter CVE ID to search for: ").strip()

    if cve_id:
        mapped_df = search_cve(cve_id, mitre_df, nist_df, commit_df, model)
        if not mapped_df.empty:
            mapped_df.to_csv(args.output_file, index=False)
            print(f"Results for CVE ID {cve_id} have been saved to {args.output_file}")
        else:
            print(f"No mappings found for CVE ID {cve_id}.")

if __name__ == "__main__":
    main()

