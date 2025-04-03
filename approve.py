import requests
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s: %(message)s',
    filename='staging_approval.log'
)

# Configuration
BASE_URL = 'http://172.23.23.48:9991/api/dictionary/staging/{}/approve/'
TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzQzNTcwNDIwLCJpYXQiOjE3NDM1NjY4MjAsImp0aSI6IjViY2JlZWQ5MDQ3OTRkMTk5MzE2Yjk3ZmVmMGQxZTkyIiwidXNlcl9pZCI6NX0.yht98oz4zfVkD848NVXGG2zmSfOZzS5DfSF67JRHVM8'  # Replace with your actual bearer token

# Headers for the request
HEADERS = {
    'Authorization': f'Bearer {TOKEN}',
    'Content-Type': 'application/json'
}

def approve_staging_entry(entry_id):
    """
    Approve a single staging entry

    :param entry_id: ID of the staging entry to approve
    :return: Tuple of (entry_id, success_status, response_message)
    """
    try:
        # Construct the full URL
        url = BASE_URL.format(entry_id)

        # Send POST request to approve the entry
        response = requests.post(url, headers=HEADERS)

        # Check the response
        if response.status_code in [200, 201]:
            logging.info(f"Successfully approved staging entry {entry_id}")
            return entry_id, True, "Approved successfully"
        else:
            logging.error(f"Failed to approve staging entry {entry_id}. Status: {response.status_code}, Response: {response.text}")
            return entry_id, False, response.text

    except requests.RequestException as e:
        logging.error(f"Request error for entry {entry_id}: {str(e)}")
        return entry_id, False, str(e)
    except Exception as e:
        logging.error(f"Unexpected error for entry {entry_id}: {str(e)}")
        return entry_id, False, str(e)

def bulk_approve_entries(start_id=9, end_id=88, max_workers=5):
    """
    Bulk approve staging entries with concurrent processing

    :param start_id: Starting ID of staging entries
    :param end_id: Ending ID of staging entries
    :param max_workers: Maximum number of concurrent threads
    """
    # Track results
    successful_approvals = []
    failed_approvals = []

    # Use ThreadPoolExecutor for concurrent processing
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Create futures for all entries
        futures = {
            executor.submit(approve_staging_entry, entry_id): entry_id
            for entry_id in range(start_id, end_id + 1)
        }

        # Process results as they complete
        for future in as_completed(futures):
            entry_id = futures[future]
            try:
                # Get the result of the future
                _, success, message = future.result()

                if success:
                    successful_approvals.append(entry_id)
                else:
                    failed_approvals.append((entry_id, message))

                # Optional: Add a small delay between requests to prevent rate limiting
                time.sleep(0.5)

            except Exception as e:
                failed_approvals.append((entry_id, str(e)))

    # Log summary
    logging.info("\n--- APPROVAL SUMMARY ---")
    logging.info(f"Total Entries Processed: {len(range(start_id, end_id + 1))}")
    logging.info(f"Successful Approvals: {len(successful_approvals)}")
    logging.info(f"Failed Approvals: {len(failed_approvals)}")

    # Detailed logging of failures
    if failed_approvals:
        logging.error("Failed Entries:")
        for entry_id, message in failed_approvals:
            logging.error(f"Entry {entry_id}: {message}")

    return successful_approvals, failed_approvals

def main():
    # Retry mechanism for failed entries
    start_id, end_id = 9, 88
    max_retries = 3

    for attempt in range(max_retries):
        logging.info(f"\nApproval Attempt {attempt + 1}")

        successful, failed = bulk_approve_entries(start_id, end_id)

        # If no failures, we're done
        if not failed:
            logging.info("All entries approved successfully!")
            break

        # Prepare for retry with only failed entries
        failed_ids = [entry_id for entry_id, _ in failed]
        start_id = min(failed_ids)
        end_id = max(failed_ids)

        # Wait before retry
        time.sleep(5)

    logging.info("Bulk approval process completed.")

if __name__ == '__main__':
    main()
