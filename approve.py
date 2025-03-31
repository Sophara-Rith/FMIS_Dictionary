import requests
import os
from dotenv import load_dotenv

load_dotenv()

class StagingEntryApprover:
    def __init__(self, base_url, username, password):
        """
        Initialize the approver with authentication credentials

        :param base_url: Base URL of the API
        :param username: Admin username
        :param password: Admin password
        """
        self.base_url = base_url.rstrip('/')
        self.username = 'sophara12345'
        self.password = 'Fmi$2025'
        self.token = self.get_access_token()

    def approve_staging_entry(self, entry_id):
        """
        Approve a specific staging entry

        :param entry_id: ID of the staging entry to approve
        :return: Response from the approval endpoint
        """
        approve_url = f"{self.base_url}/api/dictionary/staging/{entry_id}/approve/"
        headers = {
            'Authorization': f'Bearer {self.token}',
            'Content-Type': 'application/json'
        }

        try:
            response = requests.post(approve_url, headers=headers)
            response.raise_for_status()
            return response
        except requests.exceptions.RequestException as e:
            print(f"Error approving entry {entry_id}: {e}")
            return None

def main():
    # Retrieve credentials from environment variables
    BASE_URL = 'http://127.0.0.1:3030'
    ADMIN_USERNAME = 'sophara12345'
    ADMIN_PASSWORD = 'Fmi$2025'

    if not all([BASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD]):
        print("Please set BASE_URL, ADMIN_USERNAME, and ADMIN_PASSWORD in your .env file")
        return

    # Initialize the approver
    approver = StagingEntryApprover(BASE_URL, ADMIN_USERNAME, ADMIN_PASSWORD)

    # Approve entries from ID 1 to 32
    successful_approvals = []
    failed_approvals = []

    for entry_id in range(1, 33):
        print(f"Attempting to approve staging entry {entry_id}...")
        response = approver.approve_staging_entry(entry_id)

        if response and response.status_code == 200:
            print(f"✅ Successfully approved entry {entry_id}")
            successful_approvals.append(entry_id)
        else:
            print(f"❌ Failed to approve entry {entry_id}")
            failed_approvals.append(entry_id)

    # Summary report
    print("\n--- Approval Summary ---")
    print(f"Total Entries Processed: {len(range(1, 33))}")
    print(f"Successful Approvals: {len(successful_approvals)}")
    print(f"Failed Approvals: {len(failed_approvals)}")

    if failed_approvals:
        print("Failed Entry IDs:", failed_approvals)

if __name__ == "__main__":
    main()
