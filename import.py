import json
import requests

def insert_dictionary_data(json_file_path, api_url, auth_token):
    # Read the JSON file
    with open(json_file_path, 'r', encoding='utf-8') as file:
        json_data = json.load(file)

    # Headers for the API request
    headers = {
        'Content-Type': 'application/json',
        'Authorization': f'Bearer {auth_token}'  # Replace with your actual auth method
    }

    # Track successful and failed insertions
    successful_insertions = []
    failed_insertions = []

    # Iterate through the data
    for table in json_data:
        if table['type'] == 'table' and 'data' in table:
            for entry in table['data']:
                # Prepare the payload
                payload = {
                    'word_kh': entry.get('word_kh', ''),
                    'word_en': entry.get('word_en', ''),
                    'word_en_type': entry.get('type', ''),
                    'word_kh_type': 'នាម',
                    'word_kh_definition': entry.get('detail', ''),
                    'word_en_definition': entry.get('detail', '')

                }

                try:
                    # Send POST request to the API
                    response = requests.post(api_url, json=payload, headers=headers)

                    # Check if the request was successful
                    if response.status_code in [200, 201]:
                        successful_insertions.append(entry)
                        print(f"Successfully inserted: {entry['word_kh']} - {entry['word_en']}")
                    else:
                        failed_insertions.append({
                            'entry': entry,
                            'status_code': response.status_code,
                            'response': response.text
                        })
                        print(f"Failed to insert: {entry['word_kh']} - {response.text}")

                except requests.RequestException as e:
                    failed_insertions.append({
                        'entry': entry,
                        'error': str(e)
                    })
                    print(f"Request error for {entry['word_kh']}: {e}")

    # Summary of insertions
    print("\nInsertion Summary:")
    print(f"Total entries processed: {len(table['data'])}")
    print(f"Successful insertions: {len(successful_insertions)}")
    print(f"Failed insertions: {len(failed_insertions)}")

    # Optionally, log failed insertions to a file
    if failed_insertions:
        with open('failed_insertions.json', 'w', encoding='utf-8') as f:
            json.dump(failed_insertions, f, ensure_ascii=False, indent=2)

# Usage
if __name__ == '__main__':
    JSON_FILE_PATH = 'testData.json'
    API_URL = 'http://127.0.0.1:3030/api/dictionary/staging/create/'
    AUTH_TOKEN = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzQ1MzczNjk1LCJpYXQiOjE3NDUzNzAwOTUsImp0aSI6IjJlY2I2MDk2MDAzMzQyM2RiZjllNzU3ODJiM2MwMjJhIiwidXNlcl9pZCI6MjB9.sjGDcTpKtdcVucbkJ92nB-eTF89BbXkcZP5rgVS-2MA'

    insert_dictionary_data(JSON_FILE_PATH, API_URL, AUTH_TOKEN)
