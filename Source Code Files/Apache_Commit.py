import os
import requests
import csv
import time

# GitHub API endpoint for the Apache HTTPd repository
repo_owner = "apache"
repo_name = "httpd"
base_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}"

# Read token from environment variable to avoid hardcoding credentials in source
token = os.environ.get("GITHUB_TOKEN", "")
headers = {"Authorization": f"token {token}"} if token else {}


def get_paginated_data(url):
    results = []
    page = 1
    per_page = 100  # Max allowed by GitHub

    while True:
        response = requests.get(url, headers=headers, params={"page": page, "per_page": per_page})
        if response.status_code != 200:
            print(f"Error: {response.status_code} - {response.text}")
            break

        data = response.json()
        if not data:
            break  # Stop if there is no more data

        results.extend(data)
        page += 1
        time.sleep(0.1)  # Slight delay to avoid hitting rate limits

    return results


def get_commits():
    commits_url = f"{base_url}/commits"
    return get_paginated_data(commits_url)


def get_pull_requests():
    prs_url = f"{base_url}/pulls"
    return get_paginated_data(prs_url)


def get_issues():
    issues_url = f"{base_url}/issues"
    return get_paginated_data(issues_url)


def main():
    commits = get_commits()
    pull_requests = get_pull_requests()
    issues = get_issues()

    filename = "github_data.csv"

    with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(['Commit SHA', 'Commit Message', 'PR Title', 'Issue Title'])

        for commit in commits:
            commit_sha = commit['sha']
            commit_message = commit['commit']['message']

            pr_title = ""
            for pr in pull_requests:
                if pr['merge_commit_sha'] == commit_sha:
                    pr_title = pr['title']
                    break

            issue_title = ""
            for issue in issues:
                if issue['body'] and commit_sha in issue['body']:
                    issue_title = issue['title']
                    break

            writer.writerow([commit_sha, commit_message, pr_title, issue_title])

    print(f"Data successfully saved to {filename}")


if __name__ == "__main__":
    main()
