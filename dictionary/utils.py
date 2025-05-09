# dictionary/utils.py
import os
import uuid
import pandas as pd
from django.conf import settings
from .models import WordType

class DictionaryTemplateGenerator:
    @classmethod
    def generate_template(cls, output_dir=None):
        """
        Generate a comprehensive Excel template for dictionary imports
        """
        # Determine output directory
        if output_dir is None:
            output_dir = os.path.join(
                settings.BASE_DIR,
                'tmp',
                'import_templates'
            )

        # Ensure directory exists
        os.makedirs(output_dir, exist_ok=True)

        # Generate unique filename with timestamp
        unique_id = uuid.uuid4().hex[:8]
        filename = f'dictionary_import_template_{unique_id}.xlsx'
        full_path = os.path.join(output_dir, filename)

        try:
            # Prepare template data
            template_data = cls._prepare_template_data()

            # Create Excel writer
            with pd.ExcelWriter(full_path, engine='xlsxwriter') as writer:
                # Write main sheet
                template_data.to_excel(writer, index=False, sheet_name='Dictionary Entries')

                # Get workbook and worksheet objects
                workbook = writer.book
                worksheet = writer.sheets['Dictionary Entries']

                # Apply formatting and validation
                cls._format_worksheet(workbook, worksheet, template_data)

                # Add instructions sheet
                cls._add_instructions_sheet(workbook)

            return full_path

        except Exception as e:
            import logging
            logger = logging.getLogger(__name__)
            logger.error(f"Template Generation Error: {str(e)}", exc_info=True)
            raise

    @classmethod
    def _prepare_template_data(cls):
        """
        Prepare initial template data with Khmer headers
        """
        data = {
            'ល.រ': [1],
            'ពាក្យខ្មែរ': ['Example Khmer Word'],
            'ថ្នាក់ពាក្យខ្មែរ': [WordType.WORD_TYPE_CHOICES_KH[0][0]],
            'និយមន័យ': ['Khmer word definition'],
            'ពាក្យអង់គ្លេស': ['Example English Word'],
            'ថ្នាក់ពាក្យអង់គ្លេស': [WordType.WORD_TYPE_MAP[WordType.WORD_TYPE_CHOICES_KH[0][0]]],
            'និយមន័យអង់គ្លេស': ['English word definition'],
            'ការបញ្ចេញសំឡេងខ្មែរ': ['Khmer pronunciation'],
            'ការបញ្ចេញសំឡេងអង់គ្លេស': ['English pronunciation'],
            'ឧទាហរណ៍ខ្មែរ': ['Example sentence in Khmer'],
            'ឧទាហរណ៍អង់គ្លេស': ['Example sentence in English']
        }

        return pd.DataFrame(data)

    @classmethod
    def _format_worksheet(cls, workbook, worksheet, template_data):
        """
        Apply formatting, validation, and minimal protection to the worksheet

        Args:
            workbook: Excel workbook object
            worksheet: Excel worksheet object
            template_data: DataFrame with template data
        """
        # Header format - locked and styled
        header_format = workbook.add_format({
            'bg_color': '#DCE6F1',
            'align': 'center',
            'valign': 'vcenter',
            'border': 1,
            'locked': True,  # Ensure header is locked
            'font_color': '#000000',
            'font_name': 'Khmer OS Muol Light',
            'text_wrap': True
        })

        # Data format - unlocked
        data_format = workbook.add_format({
            'locked': False,  # Allow data entry
            'font_name': 'Khmer OS Siemreap'
        })

        # Apply header formatting
        for col_num, value in enumerate(template_data.columns):
            # Write header with locked format
            worksheet.write(0, col_num, value, header_format)

        # Prepare type choices
        kh_types = [t[0] for t in WordType.WORD_TYPE_CHOICES_KH]
        en_types = [t[0] for t in WordType.WORD_TYPE_CHOICES_EN]

        # Add data validation for word types
        worksheet.data_validation('C2:C1048576', {
            'validate': 'list',
            'source': kh_types
        })

        worksheet.data_validation('F2:F1048576', {
            'validate': 'list',
            'source': en_types
        })

        # Set column widths
        column_widths = [10, 20, 15, 30, 20, 15, 30, 20, 20, 30, 30]
        for col_num, width in enumerate(column_widths):
            worksheet.set_column(col_num, col_num, width, data_format)

        # Minimal worksheet protection - only first row locked
        worksheet.protect(
            options={
                'sheet': True,
                'format_cells': True,
                'format_columns': True,
                'format_rows': True,
                'insert_columns': False,
                'insert_rows': False,
                'insert_hyperlinks': False,
                'delete_columns': False,
                'delete_rows': False,
                'select_locked_cells': True,
                'sort': False,
                'autofilter': False,
                'pivot_tables': False,
                'select_unlocked_cells': True
            }
        )

        # Lock only the first row
        worksheet.set_row(0, None, None, {'locked': True})

    @classmethod
    def _add_instructions_sheet(cls, workbook):
        """
        Add an instructions sheet to the workbook

        Args:
            workbook: Excel workbook object
        """
        # Create instructions worksheet
        worksheet = workbook.add_worksheet('Instructions')

        # Prepare instruction content with strong warnings
        instructions = [
            ("IMPORT INSTRUCTIONS", "bold"),
            ("IMPORTANT: DO NOT MODIFY COLUMN HEADERS", "warning"),
            ("1. Fill in the 'Dictionary Entries' sheet", "normal"),
            ("2. Column Descriptions:", "bold"),
            ("   - Headers are LOCKED and CANNOT be changed", "warning"),
            ("   - id: Unique identifier (auto-generated)", "normal"),
            ("   - word_kh: Khmer word (required)", "normal"),
            ("   - word_kh_type: Select from dropdown (required)", "normal"),
            ("   - word_kh_definition: Khmer word definition (required)", "normal"),
            ("   - word_en: English word (required)", "normal"),
            ("   - word_en_type: Select from dropdown (required)", "normal"),
            ("   - word_en_definition: English word definition (required)", "normal"),
            ("3. Optional Columns:", "bold"),
            ("   - pronunciation_kh: Khmer pronunciation", "normal"),
            ("   - pronunciation_en: English pronunciation", "normal"),
            ("   - example_sentence_kh: Example in Khmer", "normal"),
            ("   - example_sentence_en: Example in English", "normal"),
            ("4. WARNINGS:", "warning"),
            ("   - Modifying headers will BREAK the import process", "warning"),
            ("   - Use ONLY the provided dropdowns for word types", "warning"),
            ("5. Word Type Choices:", "bold"),
            ("   Khmer Word Types:", "normal")
        ]

        # Add Khmer word type choices
        instructions.extend(
            [(f"   - {t[0]}: {t[1]}", "normal")
             for t in WordType.WORD_TYPE_CHOICES_KH]
        )

        instructions.extend([
            ("   English Word Types:", "normal")
        ])

        # Add English word type choices
        instructions.extend(
            [(f"   - {t[0]}: {t[1]}", "normal")
             for t in WordType.WORD_TYPE_CHOICES_EN]
        )

        # Create formats
        bold_format = workbook.add_format({
            'bold': True,
            'font_size': 11,
            'text_wrap': True
        })
        normal_format = workbook.add_format({
            'font_size': 10,
            'text_wrap': True
        })
        warning_format = workbook.add_format({
            'bold': True,
            'font_size': 10,
            'font_color': 'red',
            'text_wrap': True
        })

        # Write instructions
        for row, (text, format_type) in enumerate(instructions):
            if format_type == 'bold':
                fmt = bold_format
            elif format_type == 'warning':
                fmt = warning_format
            else:
                fmt = normal_format

            worksheet.write(row, 0, text, fmt)

        # Adjust column width
        worksheet.set_column(0, 0, 50)

def generate_unique_task_id():
    """
    Generate a unique task identifier
    """
    return str(uuid.uuid4())

def format_date(date_obj):
    """
    Convert datetime object to 'DD-MM-YYYY' format
    """
    if not date_obj:
        return None
    return date_obj.strftime('%d-%m-%Y')

def convert_to_khmer_number(text):
    """
    Convert Latin numbers to Khmer numbers
    """
    latin_to_khmer = {
        '0': '០',
        '1': '១',
        '2': '២',
        '3': '៣',
        '4': '៤',
        '5': '៥',
        '6': '៦',
        '7': '៧',
        '8': '៨',
        '9': '៩'
    }

    # If input is None or not a string, return as is
    if not isinstance(text, str):
        return text

    # Convert each Latin digit to Khmer
    return ''.join(latin_to_khmer.get(char, char) for char in text)

def convert_to_khmer_date(date_str):
    """
    Convert Gregorian date to Khmer date format

    Args:
        date_str (str): Date in format 'DD-MM-YYYY'

    Returns:
        str: Date in Khmer format 'DD-Month-YYYY'
    """
    # Khmer month names
    khmer_months = {
        '01': 'មករា',
        '02': 'កុម្ភៈ',
        '03': 'មីនា',
        '04': 'មេសា',
        '05': 'ឧសភា',
        '06': 'មិថុនា',
        '07': 'កក្កដា',
        '08': 'សីហា',
        '09': 'កញ្ញា',
        '10': 'តុលា',
        '11': 'វិច្ឆិកា',
        '12': 'ធ្នូ'
    }

    # Khmer number mapping
    khmer_numbers = {
        '0': '០', '1': '១', '2': '២', '3': '៣', '4': '៤',
        '5': '៥', '6': '៦', '7': '៧', '8': '៨', '9': '៩'
    }

    def convert_to_khmer_number(num_str):
        return ''.join(khmer_numbers.get(digit, digit) for digit in num_str)

    try:
        # Split the date
        day, month, year = date_str.split('-')

        # Convert to Khmer
        khmer_day = convert_to_khmer_number(day)
        khmer_month = khmer_months.get(month, month)
        khmer_year = convert_to_khmer_number(year)

        return f"{khmer_day}-{khmer_month}-{khmer_year}"

    except Exception as e:
        # If conversion fails, return original string
        return date_str

def format_phone_number(phone_number):
    """
    Format phone number by splitting into groups of 3 digits
    """
    # Remove any existing spaces or non-digit characters
    cleaned_number = ''.join(filter(str.isdigit, str(phone_number)))

    # Handle different phone number lengths
    if len(cleaned_number) < 9:
        return cleaned_number  # Return original if too short

    # Different formatting based on number length
    if len(cleaned_number) == 9:
        return f"{cleaned_number[:3]} {cleaned_number[3:6]} {cleaned_number[6:]}"
    elif len(cleaned_number) == 10:
        return f"{cleaned_number[:3]} {cleaned_number[3:6]} {cleaned_number[6:]}"
    else:
        return ' '.join([
            cleaned_number[:3],  # First 3 digits
            cleaned_number[3:6],  # Next 3 digits
            cleaned_number[6:]    # Remaining digits
        ])
