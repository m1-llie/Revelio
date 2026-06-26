import os
import time
import json
import requests
from tqdm import tqdm

API_KEY = "753146f0-3fe8-4bcf-95c5-f29253c0bb77"

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
RESULTS_PER_PAGE = 2000   # maximum allowed
OUTPUT_FILE = "/srv/share/revelio/all_cves.json"

HEADERS = {}
if API_KEY:
    HEADERS["apiKey"] = API_KEY


def fetch_cves(start_index):
    params = {
        "startIndex": start_index,
        "resultsPerPage": RESULTS_PER_PAGE
    }

    r = requests.get(BASE_URL, headers=HEADERS, params=params)
    r.raise_for_status()
    return r.json()


def main():
    print("Fetching CVE metadata from NVD...")

    first = fetch_cves(0)

    total_results = first["totalResults"]
    print(f"Total CVEs: {total_results}")

    all_cves = []
    all_cves.extend(first["vulnerabilities"])

    progress = tqdm(
        total=total_results,
        initial=len(first["vulnerabilities"]),
        unit="cve"
    )

    start_index = RESULTS_PER_PAGE

    while start_index < total_results:
        data = fetch_cves(start_index)

        vulns = data.get("vulnerabilities", [])
        all_cves.extend(vulns)

        progress.update(len(vulns))
        start_index += RESULTS_PER_PAGE

        # NVD rate limiting
        time.sleep(0.6 if API_KEY else 6)

    progress.close()

    print(f"Writing {len(all_cves)} CVEs to {OUTPUT_FILE}")

    with open(OUTPUT_FILE, "w") as f:
        json.dump(all_cves, f)

    print("Done.")


if __name__ == "__main__":
    main()

