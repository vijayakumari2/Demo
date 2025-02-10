import os
import json
import requests
from fuzzywuzzy import fuzz
import openai

# Load API keys
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

# GitHub Repo Details
OWNER = "your-github-org"
REPO = "your-repo-name"
HEADERS = {"Authorization": f"token {GITHUB_TOKEN}", "Accept": "application/vnd.github.v3+json"}

# GitHub Actions Metadata
GITHUB_RUN_ID = os.getenv("GITHUB_RUN_ID", "UnknownRun")
GITHUB_RUN_NUMBER = os.getenv("GITHUB_RUN_NUMBER", "UnknownRun")
GITHUB_BRANCH = os.getenv("GITHUB_BRANCH", "UnknownBranch")

# OpenAI Configuration
openai.api_key = OPENAI_API_KEY

def extract_vulnerabilities(report_file):
    """Extract vulnerabilities using AI from a ZAP JSON report."""
    try:
        with open(report_file, "r") as f:
            report_data = json.load(f)
    except json.JSONDecodeError:
        print(f"❌ Error: Failed to parse {report_file}")
        return []

    findings = report_data.get("alerts", [])
    extracted_vulnerabilities = []

    for finding in findings:
        ai_prompt = f"""
        Analyze this vulnerability from a ZAP report:
        - Name: {finding.get('name')}
        - Description: {finding.get('description')}
        - Risk Level: {finding.get('risk')}
        - URL: {finding.get('url')}
        - Solution: {finding.get('solution')}

        Extract key information in a structured format.
        """

        try:
            response = openai.ChatCompletion.create(
                model="gpt-4",
                messages=[{"role": "user", "content": ai_prompt}],
            )
            ai_analysis = response["choices"][0]["message"]["content"]
        except Exception as e:
            print(f"❌ AI Analysis Error: {e}")
            ai_analysis = "AI Analysis failed."

        extracted_vulnerabilities.append({"original": finding, "ai_analysis": ai_analysis})
    
    return extracted_vulnerabilities

def get_existing_issues():
    """Fetch existing GitHub issues."""
    url = f"https://api.github.com/repos/{OWNER}/{REPO}/issues"
    response = requests.get(url, headers=HEADERS)
    
    if response.status_code != 200:
        print(f"❌ Failed to fetch issues: {response.text}")
        return []

    return response.json()

def create_or_update_issue(vuln):
    """Create a new issue or update an existing one if it's a duplicate."""
    existing_issues = get_existing_issues()
    
    # Issue title with GitHub workflow info
    title = f"🔴 [{GITHUB_BRANCH}] Security Alert (Run #{GITHUB_RUN_NUMBER}): {vuln['original']['name']}"

    body = f"""
    **🔍 Vulnerability Detected**
    - **Name:** {vuln['original']['name']}
    - **Risk Level:** {vuln['original']['risk']}
    - **Affected URL:** {vuln['original']['url']}
    - **Suggested Fix:** {vuln['original']['solution']}
    
    **🧠 AI Analysis:**
    {vuln['ai_analysis']}

    **🛠 Workflow Details**
    - **Workflow Run:** [#{GITHUB_RUN_NUMBER}](https://github.com/{OWNER}/{REPO}/actions/runs/{GITHUB_RUN_ID})
    - **Triggered Branch:** `{GITHUB_BRANCH}`
    """

    # Check for duplicates using fuzzy matching
    for issue in existing_issues:
        if fuzz.ratio(title.lower(), issue["title"].lower()) > 85:
            print(f"🔄 Updating existing issue: {issue['title']}")
            issue_number = issue["number"]
            update_url = f"https://api.github.com/repos/{OWNER}/{REPO}/issues/{issue_number}/comments"
            
            response = requests.post(update_url, headers=HEADERS, json={"body": body})
            if response.status_code != 201:
                print(f"❌ Failed to update issue: {response.text}")
            return

    # Create a new issue if no duplicate found
    print(f"🆕 Creating new issue: {title}")
    issue_data = {"title": title, "body": body}
    response = requests.post(f"https://api.github.com/repos/{OWNER}/{REPO}/issues", headers=HEADERS, json=issue_data)
    
    if response.status_code != 201:
        print(f"❌ Failed to create issue: {response.text}")

def main():
    """Main execution function to scan files and create GitHub issues."""
    report_directory = "zap_reports"
    # report_files = [f for f in os.listdir() if f.startswith("zap_") and f.endswith(".json")]
    report_files = [f for f in os.listdir(report_directory) if f.startswith("zap_") and f.endswith(".json")]

    
    if not report_files:
        print("🚫 No ZAP JSON reports found.")
        return
    
    for report in report_files:
        report_path = os.path.join(report_directory, report)
        print(f"🔍 Processing {report_path}...")
        vulnerabilities = extract_vulnerabilities(report_path)
        for vuln in vulnerabilities:
            create_or_update_issue(vuln)

        # print(f"🔍 Processing {report}...")
        # vulnerabilities = extract_vulnerabilities(report)
        # for vuln in vulnerabilities:
        #     create_or_update_issue(vuln)

if __name__ == "__main__":
    main()
