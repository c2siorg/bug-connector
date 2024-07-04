import requests
import schedule
import time
import os
import csv
from datetime import datetime
import hashlib

URL = "https://cve.mitre.org/data/downloads/allitems.csv"
LOCAL_FILE = "mitre_allitems.csv"
LAST_HASH_FILE = "mitre_last_hash.txt"
LOG_FILE = "mitre_cve_diff.csv"


def get_file_hash(filename):
    hash_md5 = hashlib.md5()
    with open(filename, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def download_file():
    try:
        response = requests.get(URL, timeout=30)
        response.raise_for_status()  # Raises an HTTPError for bad responses
        with open(LOCAL_FILE, 'wb') as f:
            f.write(response.content)
        print(f"File downloaded: {LOCAL_FILE}")
    except requests.RequestException as e:
        print(f"Error downloading file: {e}")
        return False
    return True


def read_last_hash():
    try:
        with open(LAST_HASH_FILE, 'r') as f:
            return f.read().strip()
    except FileNotFoundError:
        return None


def write_last_hash(file_hash):
    with open(LAST_HASH_FILE, 'w') as f:
        f.write(file_hash)


def compare_and_update():
    if download_file():
        new_hash = get_file_hash(LOCAL_FILE)
        last_hash = read_last_hash()

        if new_hash != last_hash:
            print("Changes detected in MITRE CVE data. Updating CVE list...")
            find_differences()
            write_last_hash(new_hash)
        else:
            print("No changes in MITRE CVE data.")
    else:
        print("Failed to download MITRE CVE data. Skipping update.")


def find_differences():
    last_cves = set()
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r', newline='', encoding='utf-8') as f:
            reader = csv.reader(f)
            last_cves = set(row[0] for row in reader if row[1] == 'Added')

    new_cves = set()
    with open(LOCAL_FILE, 'r', newline='', encoding='utf-8') as f:
        reader = csv.reader(f)
        next(reader)  # Skip header
        new_cves = set(row[0] for row in reader)

    added_cves = new_cves - last_cves
    removed_cves = last_cves - new_cves

    with open(LOG_FILE, 'a', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        for cve in added_cves:
            writer.writerow([cve, 'Added', datetime.now().isoformat()])
        for cve in removed_cves:
            writer.writerow([cve, 'Removed', datetime.now().isoformat()])

    print(f"Added CVEs: {len(added_cves)}")
    print(f"Removed CVEs: {len(removed_cves)}")
    print(f"Differences appended to {LOG_FILE}")


def monthly_job():
    print(f"Running monthly MITRE CVE update job at {datetime.now()}...")
    compare_and_update()


def schedule_job():
    schedule.every().day.at("00:00").do(check_and_run_monthly_job)
    print(f"Job scheduled. It will run on the first day of each month at midnight.")


def check_and_run_monthly_job():
    if datetime.now().day == 1:
        monthly_job()
    else:
        print(f"Not the first day of the month. Skipping MITRE CVE update at {datetime.now()}.")


# Initial download and update


print("Performing initial download and update...")
compare_and_update()

# Schedule future updates
schedule_job()

# Keep the script running
while True:
    schedule.run_pending()
    time.sleep(1)
