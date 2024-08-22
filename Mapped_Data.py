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
def map_cves_to_commits(cve_df, commit_df, model, threshold=0.7):
    # Ensure the 'description' column exists; if not, print available columns
    if 'description' not in cve_df.columns:
        print("Error: 'description' column not found in CVE DataFrame. Available columns:")
        print(cve_df.columns.tolist())
        return pd.DataFrame()  # Return an empty DataFrame to avoid further errors
    
    # Convert commit messages and CVE descriptions to lists for easier processing
    commit_messages = commit_df['Commit_Message'].tolist()
    cve_descriptions = cve_df['Description'].tolist()

    # Encode commit messages and CVE descriptions using the model to generate embeddings
    print("Encoding commit messages and CVE descriptions...")
    commit_embeddings = model.encode(commit_messages, convert_to_tensor=True)
    cve_embeddings = model.encode(cve_descriptions, convert_to_tensor=True)

    mapped_data = []

    # Compute cosine similarities between all commits and all CVEs
    print("Computing cosine similarities between commits and CVEs...")
    cosine_scores = util.cos_sim(cve_embeddings, commit_embeddings)

    # Loop over CVEs and find the best matching commit based on similarity score
    for cve_idx in range(len(cve_df)):
        cve_row = cve_df.iloc[cve_idx]
        cve_id = cve_row.get('CVE ID', '')  # From NIST data
        cve_description = cve_row.get('Description', '')

        # Get the similarity scores for the current CVE against all commits
        scores = cosine_scores[cve_idx]
        
        # Extract the most similar commits that meet the threshold
        for commit_idx, score in enumerate(scores):
            if score >= threshold:  # Only consider matches above the threshold
                commit_row = commit_df.iloc[commit_idx]
                commit_message = commit_row.get('Commit_Message', '')

                # Store the results
                mapped_data.append({
                    'CVE_ID': cve_id,  # From NIST data
                    'Commit_Message': commit_message,
                    'Similarity_Score': score.item(),  # Cosine similarity score
                })

    return pd.DataFrame(mapped_data)

# Main execution
if __name__ == "__main__":
    # Load the pre-trained sentence-transformer model (SBERT for semantic similarity)
    model = SentenceTransformer('paraphrase-MiniLM-L6-v2')  # Lightweight and efficient model

    # Load your CSV files (NIST CVE data and Apache commit data)
    cve_file_path = r'C:\Users\ADMIN\Desktop\bug-connector\NIST_cve_data.csv'
    commit_file_path = r'C:\Users\ADMIN\Desktop\bug-connector\Apache_cve_data.csv'

    # Load CSVs and print column names
    cve_df = load_csv(cve_file_path)
    commit_df = load_csv(commit_file_path)

    if not cve_df.empty and not commit_df.empty:
        # Extract CVE IDs and commit messages from 'title/message' in Apache data
        commit_df = extract_commit_data(commit_df)

        # Map commits to CVEs based on semantic similarity
        mapped_df = map_cves_to_commits(cve_df, commit_df, model)

        # If the mapping was successful, save the results
        if not mapped_df.empty:
            output_file_path = r'C:\Users\ADMIN\Desktop\bug-connector\mapped_file.csv'
            mapped_df.to_csv(output_file_path, index=False)
            print(f"Mapped data saved to {output_file_path}")
    else:
        print("One or more CSV files could not be loaded. Exiting the script.")
