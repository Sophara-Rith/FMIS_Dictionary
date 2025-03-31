import requests
import json
import os
import uuid
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

entries=[
  {
    "word_kh": "សៀវភៅ",
    "word_kh_type": "នាម",
    "word_kh_definition": "វត្ថុសម្រាប់កត់ត្រា ឬអាន",
    "word_en": "Book",
    "word_en_type": "NOUN",
    "word_en_definition": "A written or printed work consisting of pages glued or sewn together along one side and bound in covers.",
    "pronunciation_kh": "siəv phov",
    "pronunciation_en": "bʊk",
    "example_sentence_kh": "ខ្ញុំកំពុងអានសៀវភៅមួយក្បាល។",
    "example_sentence_en": "I am reading a book."
  },
  {
    "word_kh": "តុ",
    "word_kh_type": "នាម",
    "word_kh_definition": "គ្រឿងសង្ហារឹមដែលមានផ្ទៃរាបស្មើ",
    "word_en": "Table",
    "word_en_type": "NOUN",
    "word_en_definition": "A piece of furniture with a flat top supported by legs.",
    "pronunciation_kh": "toʊ",
    "pronunciation_en": "ˈteɪbəl",
    "example_sentence_kh": "សូមដាក់សៀវភៅលើតុ។",
    "example_sentence_en": "Please put the book on the table."
  },
  {
    "word_kh": "កៅអី",
    "word_kh_type": "នាម",
    "word_kh_definition": "គ្រឿងសង្ហារឹមសម្រាប់អង្គុយ",
    "word_en": "Chair",
    "word_en_type": "NOUN",
    "word_en_definition": "A seat for one person, typically with a back and four legs.",
    "pronunciation_kh": "kao ei",
    "pronunciation_en": "tʃeər",
    "example_sentence_kh": "អង្គុយលើកៅអីនេះទៅ។",
    "example_sentence_en": "Sit on this chair."
  },
  {
    "word_kh": "ទ្វារ",
    "word_kh_type": "នាម",
    "word_kh_definition": "វត្ថុសម្រាប់បិទបើកច្រកចូល",
    "word_en": "Door",
    "word_en_type": "NOUN",
    "word_en_definition": "A hinged, sliding, or revolving barrier at the entrance to a building, room, or vehicle.",
    "pronunciation_kh": "tʋiər",
    "pronunciation_en": "dɔːr",
    "example_sentence_kh": "សូមបិទទ្វារផង។",
    "example_sentence_en": "Please close the door."
  },
  {
    "word_kh": "បង្អួច",
    "word_kh_type": "នាម",
    "word_kh_definition": "រន្ធសម្រាប់ខ្យល់ និងពន្លឺ",
    "word_en": "Window",
    "word_en_type": "NOUN",
    "word_en_definition": "An opening in a wall or roof of a building or vehicle that is fitted with glass or other transparent material in a frame to admit light or air and allow people to see out.",
    "pronunciation_kh": "bɑng aoʊc",
    "pronunciation_en": "ˈwɪndoʊ",
    "example_sentence_kh": "បើកបង្អួចបន្តិចមក។",
    "example_sentence_en": "Open the window a little."
  },
  {
    "word_kh": "ផ្ទះ",
    "word_kh_type": "នាម",
    "word_kh_definition": "សំណង់សម្រាប់រស់នៅ",
    "word_en": "House",
    "word_en_type": "NOUN",
    "word_en_definition": "A building for human habitation.",
    "pronunciation_kh": "pʰteah",
    "pronunciation_en": "haʊs",
    "example_sentence_kh": "ខ្ញុំរស់នៅក្នុងផ្ទះមួយខ្នងតូច។",
    "example_sentence_en": "I live in a small house."
  },
  {
    "word_kh": "ឡាន",
    "word_kh_type": "នាម",
    "word_kh_definition": "យានជំនិះមានកង់បួន",
    "word_en": "Car",
    "word_en_type": "NOUN",
    "word_en_definition": "A road vehicle, typically with four wheels, powered by an internal combustion engine or electric motor and able to carry a small number of people.",
    "pronunciation_kh": "laan",
    "pronunciation_en": "kɑːr",
    "example_sentence_kh": "ខ្ញុំបើកឡានទៅធ្វើការ។",
    "example_sentence_en": "I drive a car to work."
  },
  {
    "word_kh": "ម៉ូតូ",
    "word_kh_type": "នាម",
    "word_kh_definition": "យានជំនិះមានកង់ពីរ",
    "word_en": "Motorcycle",
    "word_en_type": "NOUN",
    "word_en_definition": "A two-wheeled vehicle powered by a motor.",
    "pronunciation_kh": "moʊtoʊ",
    "pronunciation_en": "ˈmoʊtərˌsaɪkəl",
    "example_sentence_kh": "គាត់ជិះម៉ូតូទៅផ្សារ។",
    "example_sentence_en": "He rides a motorcycle to the market."
  },
  {
    "word_kh": "កង់",
    "word_kh_type": "នាម",
    "word_kh_definition": "យានជំនិះមានកង់ពីរដែលជិះដោយជាន់ឈ្នាន់",
    "word_en": "Bicycle",
    "word_en_type": "NOUN",
    "word_en_definition": "A vehicle with two wheels in tandem, usually propelled by pedals connected to the rear wheel by a chain, and steered by a handlebar connected to the front wheel.",
    "pronunciation_kh": "kɑŋ",
    "pronunciation_en": "ˈbaɪsɪkəl",
    "example_sentence_kh": "ខ្ញុំជិះកង់ទៅសាលារៀន។",
    "example_sentence_en": "I ride a bicycle to school."
  },
  {
    "word_kh": "ផ្លូវ",
    "word_kh_type": "នាម",
    "word_kh_definition": "ទីកន្លែងសម្រាប់ធ្វើដំណើរ",
    "word_en": "Road",
    "word_en_type": "NOUN",
    "word_en_definition": "A wide way leading from one place to another, especially one with a specially prepared surface that vehicles can use.",
    "pronunciation_kh": "plov",
    "pronunciation_en": "roʊd",
    "example_sentence_kh": "ផ្លូវនេះស្អាតណាស់។",
    "example_sentence_en": "This road is very beautiful."
  },
  {
    "word_kh": "ដើមឈើ",
    "word_kh_type": "នាម",
    "word_kh_definition": "រុក្ខជាតិមានដើមធំ",
    "word_en": "Tree",
    "word_en_type": "NOUN",
    "word_en_definition": "A woody perennial plant, typically having a single stem or trunk growing to a considerable height and bearing lateral branches at some distance from the ground.",
    "pronunciation_kh": "daəm chʰəə",
    "pronunciation_en": "triː",
    "example_sentence_kh": "មានដើមឈើធំមួយនៅមុខផ្ទះខ្ញុំ។",
    "example_sentence_en": "There is a big tree in front of my house."
  },
  {
    "word_kh": "ផ្កា",
    "word_kh_type": "នាម",
    "word_kh_definition": "ផ្នែកមួយនៃរុក្ខជាតិដែលមានពណ៌ស្រស់ស្អាត",
    "word_en": "Flower",
    "word_en_type": "NOUN",
    "word_en_definition": "The seed-bearing part of a plant, consisting of reproductive organs (stamens and carpels) that are typically surrounded by a brightly colored corolla (petals) and a green calyx (sepals).",
    "pronunciation_kh": "pʰkaa",
    "pronunciation_en": "ˈflaʊər",
    "example_sentence_kh": "ខ្ញុំចូលចិត្តផ្កាកុលាប។",
    "example_sentence_en": "I like roses."
  },
  {
    "word_kh": "មេឃ",
    "word_kh_type": "នាម",
    "word_kh_definition": "លំហដែលនៅពីលើផែនដី",
    "word_en": "Sky",
    "word_en_type": "NOUN",
    "word_en_definition": "The region of the atmosphere and outer space seen from the earth.",
    "pronunciation_kh": "meːk",
    "pronunciation_en": "skaɪ",
    "example_sentence_kh": "មេឃថ្ងៃនេះស្រឡះល្អណាស់។",
    "example_sentence_en": "The sky is very clear today."
  },
  {
    "word_kh": "ព្រះអាទិត្យ",
    "word_kh_type": "នាម",
    "word_kh_definition": "ផ្កាយដែលផ្តល់ពន្លឺ និងកំដៅដល់ផែនដី",
    "word_en": "Sun",
    "word_en_type": "NOUN",
    "word_en_definition": "The star around which the earth orbits.",
    "pronunciation_kh": "preah aːtet",
    "pronunciation_en": "sʌn",
    "example_sentence_kh": "ព្រះអាទិត្យកំពុងរះ។",
    "example_sentence_en": "The sun is rising."
  },
  {
    "word_kh": "ព្រះច័ន្ទ",
    "word_kh_type": "នាម",
    "word_kh_definition": "ផ្កាយរណបរបស់ផែនដី",
    "word_en": "Moon",
    "word_en_type": "NOUN",
    "word_en_definition": "The natural satellite of the earth, visible (chiefly at night) by reflected light from the sun.",
    "pronunciation_kh": "preah can",
    "pronunciation_en": "muːn",
    "example_sentence_kh": "យប់នេះព្រះច័ន្ទពេញវង់។",
    "example_sentence_en": "The moon is full tonight."
  },
  {
    "word_kh": "ទឹក",
    "word_kh_type": "នាម",
    "word_kh_definition": "សារធាតុរាវសំខាន់សម្រាប់ជីវិត",
    "word_en": "Water",
    "word_en_type": "NOUN",
    "word_en_definition": "A colorless, transparent, odorless, tasteless liquid that forms the seas, lakes, rivers, and rain and is the basis of the fluids of living organisms.",
    "pronunciation_kh": "tɨk",
    "pronunciation_en": "ˈwɔːtər",
    "example_sentence_kh": "ខ្ញុំត្រូវការផឹកទឹក។",
    "example_sentence_en": "I need to drink water."
  },
  {
    "word_kh": "ភ្លើង",
    "word_kh_type": "នាម",
    "word_kh_definition": "កំដៅ និងពន្លឺដែលបញ្ចេញចេញពីការឆេះ",
    "word_en": "Fire",
    "word_en_type": "NOUN",
    "word_en_definition": "Combustion or burning, in which substances combine chemically with oxygen from the air and typically give out bright light, heat, and smoke.",
    "pronunciation_kh": "pʰləəŋ",
    "pronunciation_en": "ˈfaɪər",
    "example_sentence_kh": "សូមប្រយ័ត្នភ្លើង។",
    "example_sentence_en": "Be careful with fire."
  },
  {
    "word_kh": "ខ្យល់",
    "word_kh_type": "នាម",
    "word_kh_definition": "ចលនានៃខ្យល់",
    "word_en": "Wind",
    "word_en_type": "NOUN",
    "word_en_definition": "The perceptible natural movement of the air, especially in the form of a current of air blowing from a particular direction.",
    "pronunciation_kh": "kʰyɑl",
    "pronunciation_en": "wɪnd",
    "example_sentence_kh": "ខ្យល់ថ្ងៃនេះត្រជាក់ណាស់។",
    "example_sentence_en": "The wind is very cold today."
  },
  {
    "word_kh": "ដី",
    "word_kh_type": "នាម",
    "word_kh_definition": "ផ្ទៃនៃផែនដី",
    "word_en": "Land",
    "word_en_type": "NOUN",
    "word_en_definition": "The part of the earth's surface that is not permanently covered by water, as opposed to the sea or the air.",
    "pronunciation_kh": "dəi",
    "pronunciation_en": "lænd",
    "example_sentence_kh": "ដីនេះសំបូរជីជាតិ។",
    "example_sentence_en": "This land is fertile."
  },
  {
    "word_kh": "ភ្នំ",
    "word_kh_type": "នាម",
    "word_kh_definition": "ដីដែលខ្ពស់ជាងគេ",
    "word_en": "Mountain",
    "word_en_type": "NOUN",
    "word_en_definition": "A large natural elevation of the earth's surface rising abruptly from the surrounding level; a large steep hill.",
    "pronunciation_kh": "pʰnum",
    "pronunciation_en": "ˈmaʊntən",
    "example_sentence_kh": "ខ្ញុំចង់ឡើងភ្នំ។",
    "example_sentence_en": "I want to climb a mountain."
  },
  {
    "word_kh": "សមុទ្រ",
    "word_kh_type": "នាម",
    "word_kh_definition": "ផ្ទៃទឹកធំ",
    "word_en": "Sea",
    "word_en_type": "NOUN",
    "word_en_definition": "The expanse of salt water that covers most of the earth's surface and surrounds its landmasses.",
    "pronunciation_kh": "sɑm.ɗɑː",
    "pronunciation_en": "siː",
    "example_sentence_kh": "ខ្ញុំចូលចិត្តហែលទឹកសមុទ្រ។",
    "example_sentence_en": "I like to swim in the sea."
  }
]

class DictionaryDataUploader:
    def __init__(self, base_url, username, password, json_file_path):
        """
        Initialize the uploader with authentication and data source

        :param base_url: Base URL of the API
        :param username: Login username
        :param password: Login password
        :param json_file_path: Path to the JSON file containing dictionary entries
        """
        self.base_url = base_url
        self.username = username
        self.password = password
        self.json_file_path = json_file_path
        self.access_token = None
        self.device_id = self._generate_device_id()

    def _generate_device_id(self):
        """
        Generate a unique device ID

        :return: Unique device ID string
        """
        import uuid
        return str(uuid.uuid4())

    def authenticate(self):
        """
        Authenticate and obtain JWT token

        :return: Boolean indicating successful authentication
        """
        try:
            # Authentication endpoint
            auth_url = f"{self.base_url}/api/token/"

            # Prepare authentication payload
            payload = {
                'login_input': 'sophara12345',
                'password': 'Fmi$2025'
            }

            # Headers including device ID
            headers = {
                'Content-Type': 'application/json'
            }

            # Send authentication request
            response = requests.post(auth_url, json=payload, headers=headers)

            # Check authentication response
            if response.status_code == 200:
                # Extract access token
                self.access_token = response.json().get('access')
                return True
            else:
                print(f"Authentication failed: {response.text}")
                return False

        except requests.exceptions.RequestException as e:
            print(f"Authentication error: {e}")
            return False

    def load_dictionary_entries(self):
        """
        Load dictionary entries from JSON file

        :return: List of dictionary entries
        """
        try:
            with open(self.json_file_path, 'r', encoding='utf-8') as file:
                return json.load(file)
        except FileNotFoundError:
            print(f"JSON file not found: {self.json_file_path}")
            return []
        except json.JSONDecodeError:
            print(f"Invalid JSON format in file: {self.json_file_path}")
            return []

    def upload_entries(self):
        """
        Upload dictionary entries to staging endpoint
        """
        # First, authenticate
        if not self.authenticate():
            print("Could not authenticate. Stopping upload.")
            return

        # Load entries
        entries = self.load_dictionary_entries()

        # Staging creation endpoint
        staging_url = f"{self.base_url}/api/dictionary/staging/create/"

        # Prepare headers
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }

        # Track successful and failed uploads
        successful_uploads = 0
        failed_uploads = 0

        # Upload each entry
        for entry in entries:
            try:
                response = requests.post(
                    staging_url,
                    json=entry,
                    headers=headers
                )

                if response.status_code == 201:  # Assuming 201 for successful creation
                    successful_uploads += 1
                    print(f"Successfully uploaded: {entry.get('word_kh', 'Unknown Word')}")
                else:
                    failed_uploads += 1
                    print(f"Failed to upload: {entry.get('word_kh', 'Unknown Word')}")
                    print(f"Response: {response.text}")

            except requests.exceptions.RequestException as e:
                failed_uploads += 1
                print(f"Error uploading entry: {e}")

        # Summary
        print("\n--- Upload Summary ---")
        print(f"Total Entries: {len(entries)}")
        print(f"Successful Uploads: {successful_uploads}")
        print(f"Failed Uploads: {failed_uploads}")

def main():
    # Configuration
    BASE_URL = 'http://127.0.0.1:3030'
    USERNAME = os.getenv('leak123', 'your_username')
    PASSWORD = os.getenv('Fmi$2025', 'your_password')
    JSON_FILE_PATH = 'data.json'  # Path to your JSON file

    # Create and run uploader
    uploader = DictionaryDataUploader(
        base_url=BASE_URL,
        username=USERNAME,
        password=PASSWORD,
        json_file_path=JSON_FILE_PATH
    )

    # Upload entries
    uploader.upload_entries()

if __name__ == "__main__":
    main()
