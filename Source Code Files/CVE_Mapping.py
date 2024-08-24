import pandas as pd
from sentence_transformers import SentenceTransformer, util  # For semantic similarity
import ssl
import urllib3

# SSL Issue Handling: Disable SSL certificate verification
ssl._create_default_https_context = ssl._create_unverified_context
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Function to load CSV and handle errors
def load_csv(file_path):
    try:
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
    commit_df['Commit_Message'] = commit_df['title/message'].apply(lambda x: x.split(': ', 1)[-1] if ': ' in x else '')  # Extract the description
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
        cve_id = cve_row.get('CVE ID', '')  # From NIST data
        cve_description = cve_row.get('Description', '')

        scores = cosine_scores[cve_idx]

        # Print similarity scores for debugging
        print(f"CVE ID: {cve_id}")
        print(f"Scores: {scores}")

        for commit_idx, score in enumerate(scores):
            if score >= threshold:
                commit_row = commit_df.iloc[commit_idx]
                commit_message = commit_row.get('Commit_Message', '')

                # Print each mapping being added
                print(f"Mapping: CVE_ID={cve_id}, Commit_Message={commit_message}, Similarity_Score={score.item()}")

                mapped_data.append({
                    'CVE_ID': cve_id,  # From NIST data
                    'Commit_Message': commit_message,
                    'Similarity_Score': score.item(),  # Cosine similarity score
                })

    return pd.DataFrame(mapped_data)

# Main execution
if __name__ == "__main__":
    model = SentenceTransformer('paraphrase-MiniLM-L6-v2')  # Lightweight and efficient model

    cve_file_path = r'C:\Users\ADMIN\Desktop\bug-connector\NIST_cve_data.csv'
    commit_file_path = r'C:\Users\ADMIN\Desktop\bug-connector\Apache_cve_data.csv'

    cve_df = load_csv(cve_file_path)
    commit_df = load_csv(commit_file_path)

    if not cve_df.empty and not commit_df.empty:
        commit_df = extract_commit_data(commit_df)

        mapped_df = map_cves_to_commits(cve_df, commit_df, model)

        if not mapped_df.empty:
            output_file_path = r'C:\Users\ADMIN\Desktop\bug-connector\Mapped_CVE_file.csv'
            mapped_df.to_csv(output_file_path, index=False)
            print(f"Mapped data saved to {output_file_path}")
        else:
            print("No data was mapped.")
    else:
        print("One or more CSV files could not be loaded. Exiting the script.")
