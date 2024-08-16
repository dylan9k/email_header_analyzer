import email
from email import policy
import re
import argparse
import sys

def analyze_headers(email_content):
    msg = email.message_from_string(email_content, policy=policy.default)
    spoof_indicators = []
    spoof_score = 0
    max_score = 0

    def add_indicator(indicator, weight):
        nonlocal spoof_score, max_score
        spoof_indicators.append(indicator)
        spoof_score += weight
        max_score += weight

    # Check Authentication-Results
    auth_results = msg.get("Authentication-Results")
    if auth_results:
        # Check SPF
        spf_match = re.search(r"spf=(\w+)", auth_results)
        if spf_match:
            spf_result = spf_match.group(1)
            if spf_result == "fail":
                add_indicator("SPF check failed", 3)
            elif spf_result == "temperror":
                add_indicator("SPF check encountered a temporary error", 2)
            else:
                max_score += 3  # Add to max score even if passed

        # Check DKIM
        dkim_match = re.search(r"dkim=(\w+)", auth_results)
        if dkim_match:
            dkim_result = dkim_match.group(1)
            if dkim_result == "fail":
                add_indicator("DKIM check failed", 3)
            elif dkim_result == "none":
                add_indicator("No DKIM signature found", 2)
            else:
                max_score += 3

        # Check DMARC
        dmarc_match = re.search(r"dmarc=(\w+)", auth_results)
        if dmarc_match:
            dmarc_result = dmarc_match.group(1)
            if dmarc_result == "fail":
                add_indicator("DMARC check failed", 3)
            elif dmarc_result == "temperror":
                add_indicator("DMARC check encountered a temporary error", 2)
            else:
                max_score += 3

        # Check CompAuth
        compauth_match = re.search(r"compauth=(\w+)", auth_results)
        if compauth_match:
            compauth_result = compauth_match.group(1)
            if compauth_result == "fail":
                add_indicator("Composite authentication failed", 3)
            else:
                max_score += 3

    # Check Received-SPF
    received_spf = msg.get("Received-SPF")
    if received_spf:
        if "TempError" in received_spf:
            add_indicator("SPF check encountered a temporary error (Received-SPF)", 2)
        else:
            max_score += 2

    # Check X-Forefront-Antispam-Report
    forefront_report = msg.get("X-Forefront-Antispam-Report")
    if forefront_report:
        if "SPM" in forefront_report:
            add_indicator("Message identified as spam", 2)
        if "SPOOF" in forefront_report:
            add_indicator("Message identified as potential spoof", 3)
    max_score += 5  # Account for potential spam and spoof checks

    # Check X-Microsoft-Antispam
    ms_antispam = msg.get("X-Microsoft-Antispam")
    if ms_antispam and "BCL:0" in ms_antispam:
        add_indicator("Low bulk complaint level (potential spam)", 1)
    max_score += 1

    # Check sender and recipient consistency
    from_header = msg.get("From")
    to_header = msg.get("To")
    if from_header and to_header:
        if from_header in to_header:
            add_indicator("Sender email appears in recipient field (potential spoof)", 3)
        max_score += 3

    # Calculate percentage
    spoof_percentage = (spoof_score / max_score * 100) if max_score > 0 else 0

    return spoof_indicators, spoof_percentage

def read_eml_file(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    except UnicodeDecodeError:
        # If UTF-8 fails, try reading as ISO-8859-1
        with open(file_path, 'r', encoding='iso-8859-1') as file:
            return file.read()
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description="Analyze email headers for potential spoofing.")
    parser.add_argument("-e", "--eml", help="Path to the .eml file to analyze", required=True)
    args = parser.parse_args()

    email_content = read_eml_file(args.eml)
    spoof_indicators, spoof_percentage = analyze_headers(email_content)

    if spoof_indicators:
        print("Potential spoofing indicators detected:")
        for indicator in spoof_indicators:
            print(f"- {indicator}")
        print(f"\nEstimated likelihood of spoofing: {spoof_percentage:.2f}%")
    else:
        print("No clear signs of spoofing detected.")
        print("\nEstimated likelihood of spoofing: 0.00%")

if __name__ == "__main__":
    main()