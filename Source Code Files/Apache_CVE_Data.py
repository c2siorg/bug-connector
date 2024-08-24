import requests
import csv
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry

# GitHub API endpoint for the Apache HTTPd repository
repo_owner = "apache"
repo_name = "httpd"
base_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"
token = "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"  # Replace with your GitHub token for higher rate limits

# Set up retry logic
def create_session():
    session = requests.Session()
    retry = Retry(
        total=5,
        backoff_factor=1,
        status_forcelist=[500, 502, 503, 504],
        allowed_methods=["GET"]  # Updated argument
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session

# Function to search for CVEs in commits
def search_commits_for_cve():
    session = create_session()
    commits_url = f"{base_url}/commits"
    results = []
    page = 1
    while True:
        try:
            response = session.get(commits_url, headers={"Authorization": f"token {token}"}, params={"per_page": 100, "page": page})
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching commits: {e}")
            break
        commits = response.json()
        if not commits:
            break  # No more commits
        for commit in commits:
            commit_message = commit['commit']['message']
            if "CVE" in commit_message:
                results.append({
                    "type": "commit",
                    "sha": commit['sha'],
                    "message": commit_message,
                    "html_url": commit['html_url']
                })
        page += 1
    return results

# Function to search for CVEs in issues
def search_issues_for_cve():
    session = create_session()
    issues_url = f"{base_url}/issues"
    results = []
    page = 1
    while True:
        try:
            response = session.get(issues_url, headers={"Authorization": f"token {token}"}, params={"per_page": 100, "page": page})
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching issues: {e}")
            break
        issues = response.json()
        if not issues:
            break  # No more issues
        for issue in issues:
            issue_title = issue.get('title', '')
            issue_body = issue.get('body', '') or ''  # Ensure body is a string
            if "CVE" in issue_title or "CVE" in issue_body:
                results.append({
                    "type": "issue",
                    "number": issue['number'],
                    "title": issue_title,
                    "html_url": issue['html_url']
                })
        page += 1
    return results

# Function to search for CVEs in pull requests
def search_pull_requests_for_cve():
    session = create_session()
    pulls_url = f"{base_url}/pulls"
    results = []
    page = 1
    while True:
        try:
            response = session.get(pulls_url, headers={"Authorization": f"token {token}"}, params={"state": "all", "per_page": 100, "page": page})
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"Error fetching pull requests: {e}")
            break
        pull_requests = response.json()
        if not pull_requests:
            break  # No more pull requests
        for pr in pull_requests:
            pr_title = pr.get('title', '')
            pr_body = pr.get('body', '') or ''  # Ensure body is a string
            if "CVE" in pr_title or "CVE" in pr_body:
                results.append({
                    "type": "pull_request",
                    "number": pr['number'],
                    "title": pr_title,
                    "html_url": pr['html_url']
                })
        page += 1
    return results

# Save results to a CSV file
def save_to_csv(data, filename="Apache_cve_data.csv"):
    fieldnames = ['type', 'sha/number', 'title/message', 'html_url']
    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for row in data:
            writer.writerow({
                'type': row['type'],
                'sha/number': row.get('sha', row.get('number', '')),
                'title/message': row.get('message', row.get('title', '')),
                'html_url': row['html_url']
            })

# Main script
def main():
    print("Searching for CVEs in commits...")
    commit_results = search_commits_for_cve()
    print(f"Found {len(commit_results)} commits with CVE references.")
    
    print("Searching for CVEs in issues...")
    issue_results = search_issues_for_cve()
    print(f"Found {len(issue_results)} issues with CVE references.")
    
    print("Searching for CVEs in pull requests...")
    pr_results = search_pull_requests_for_cve()
    print(f"Found {len(pr_results)} pull requests with CVE references.")
    
    # Combine all results
    all_results = commit_results + issue_results + pr_results
    
    # Save to CSV
    print("Saving results to CSV file...")
    save_to_csv(all_results)
    print("Done! CVE data saved to Apache_cve_data.csv")

if __name__ == "__main__":
    main()
