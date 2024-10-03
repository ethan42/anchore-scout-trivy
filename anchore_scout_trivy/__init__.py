#!/usr/bin/env python3

import argparse
import json
import matplotlib.pyplot as plt

from matplotlib_venn import venn2
from typing import Set, Tuple


def extract_cves(text: str) -> Set[str]:
    """Extract all CVE ids of the form CVE-YYYY-N* from a string"""
    import re
    return set(re.findall(r"CVE-\d{4}-\d{4,7}", text))


def extract_from_sarif(path: str) -> Tuple[Set[str], Set[str]]:
    """Process SARIF file and return observed and non-observed CVEs"""
    with open(path) as f:
        data = json.load(f)
        observed, non_observed = set(), set()
        for run in data["runs"]:
            for result in run["results"]:
                is_observed = result.get("suppressions") is not None
                cves = extract_cves(str(result))
                if is_observed:
                    observed.update(cves)
                else:
                    non_observed.update(cves)
        return observed, non_observed


def extract_from_cyclonedx(path: str) -> Tuple[Set[str], Set[str]]:
    """Process CycloneDX file and return observed and non-observed CVEs"""
    with open(path) as f:
        data = json.load(f)
        observed, non_observed = set(), set()
        for vuln in data.get("vulnerabilities", []):
            is_observed = vuln.get("analysis", {}).get("justification") is not None
            cves = extract_cves(str(vuln))
            if is_observed:
                observed.update(cves)
            else:
                non_observed.update(cves)
        return observed, non_observed


def extract_from_csv(path: str) -> Tuple[Set[str], Set[str]]:
    """Process trivy-generated CSV file and return observed and non-observed CVEs"""
    with open(path) as f:
        observed, non_observed = set(), set()
        data = f.readlines()
        for line in data:
            is_observed = line.endswith("true\n")
            cves = extract_cves(line)
            if is_observed:
                observed.update(cves)
            else:
                non_observed.update(cves)
        return observed, non_observed






def main():
    parser = argparse.ArgumentParser(description="Extract CVEs from SCA files")
    ## add argument to specify if SARIF or CycloneDX files are being processed
    # parser.add_argument("--filetype", choices=["sarif", "cyclonedx"], help="Type of file to process", default="sarif")
    # parser.add_argument("file", help="File to process")
    # args = parser.parse_args()

    # if args.filetype == "sarif":
    #     observed, non_observed = extract_from_sarif(args.file)
    # else:
    #     observed, non_observed = extract_from_cyclonedx(args.file)
    # print(f"Observed: {observed}")
    # print(f"Non-observed: {non_observed}")

    parser.add_argument("sarif", help="SARIF file to process")
    parser.add_argument("cyclonedx", help="CycloneDX file to process")
    parser.add_argument("csv", help="Trivy-generated CSV file")
    args = parser.parse_args()

    observed_sarif, non_observed_sarif = extract_from_sarif(args.sarif)
    observed_cyclonedx, non_observed_cyclonedx = extract_from_cyclonedx(args.cyclonedx)
    observed_csv, non_observed_csv = extract_from_csv(args.csv)
    plt.figure(figsize=(8, 8))
    total_cyclonedx = observed_cyclonedx | non_observed_cyclonedx
    total_sarif = observed_sarif | non_observed_sarif
    total_csv = observed_csv | non_observed_csv
    # venn = venn2([total_cyclonedx, total_csv], ('Anchore', 'Trivy'))

    # plt.title("Vulnerability Overlap for Anchore and Trivy")
    # plt.show()

    venn = venn2([total_cyclonedx, observed_cyclonedx], ('Anchore', 'Anchore + MDSBOM'))
    plt.title("Findings reduction using Dynamic SBOM for Anchore")
    plt.show()

    venn = venn2([total_csv, observed_csv], ('Trivy', 'Trivy + MDSBOM'))
    plt.title("Findings reduction using Dynamic SBOM for Trivy")
    plt.show()

    venn = venn2([total_sarif, observed_sarif], ('Scout', 'Scout + MDSBOM'))
    plt.title("Findings reduction using Dynamic SBOM for Scout")
    plt.show()





if __name__ == "__main__":
    main()

