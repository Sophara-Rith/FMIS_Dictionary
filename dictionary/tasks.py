# dictionary/tasks.py
import logging
import pandas as pd
from celery import shared_task
from django.contrib.auth import get_user_model
from django.db import transaction
from django.db.models import Q

from .models import Staging, Dictionary, WordType, RelatedWord
from .serializers import StagingEntryCreateSerializer
from users.models import ActivityLog, User

logger = logging.getLogger(__name__)
User = get_user_model()

@shared_task(bind=True)
def process_staging_bulk_import_sync(file_path, user_id, activity_log_id=None):
    """Synchronous version of the bulk import process"""
    try:
        # Retrieve user and activity log
        user = User.objects.get(id=user_id)
        activity_log = ActivityLog.objects.get(id=activity_log_id) if activity_log_id else None

        # Read Excel file
        df = pd.read_excel(file_path)

        # Prepare tracking variables
        import_results = {
            'total_entries': len(df),
            'successful_entries': 0,
            'failed_entries': [],
        }

        # Process each row
        for index, row in df.iterrows():
            try:
                # Prepare staging data
                staging_data = {
                    'word_kh': row['word_kh'],
                    'word_kh_type': row['word_kh_type'],
                    'word_kh_definition': row['word_kh_definition'],
                    'word_en': row['word_en'],
                    'word_en_type': row['word_en_type'],
                    'word_en_definition': row['word_en_definition'],
                    'pronunciation_kh': row.get('pronunciation_kh', ''),
                    'pronunciation_en': row.get('pronunciation_en', ''),
                    'example_sentence_kh': row.get('example_sentence_kh', ''),
                    'example_sentence_en': row.get('example_sentence_en', '')
                }

                # Validate and save each entry
                serializer = StagingEntryCreateSerializer(
                    data=staging_data,
                    context={'request': type('Request', (), {'user': user})()}
                )

                if serializer.is_valid():
                    staging_entry = serializer.save(created_by=user)
                    import_results['successful_entries'] += 1

                    # Process word relationships for admin/superuser
                    if user.role in ['ADMIN', 'SUPERUSER']:
                        _process_word_relationships(staging_entry)
                else:
                    import_results['failed_entries'].append({
                        'row': index + 2,
                        'word_kh': row['word_kh'],
                        'word_en': row['word_en'],
                        'errors': serializer.errors
                    })

            except Exception as row_error:
                import_results['failed_entries'].append({
                    'row': index + 2,
                    'word_kh': row.get('word_kh', ''),
                    'word_en': row.get('word_en', ''),
                    'errors': str(row_error)
                })

        return import_results

    except Exception as e:
        logger.error(f"Sync bulk import failed: {str(e)}", exc_info=True)
        raise

def _process_word_relationships(staging_entry):
    """
    Process word relationships for staging entries
    """
    words = staging_entry.word_en.split()

    # Single word scenario
    if len(words) == 1:
        staging_entry.is_parent = True
        staging_entry.is_child = False
        staging_entry.save()
        return

    # Multi-word scenario
    staging_entry.is_parent = False

    # Check for potential parent words in Dictionary
    potential_parents = Dictionary.objects.filter(
        Q(word_en__in=words) & Q(is_parent=True)
    )

    if potential_parents.exists():
        # This is likely a compound or derived word
        staging_entry.is_child = True
    else:
        # No existing parent words found
        staging_entry.is_parent = len(words) > 1
        staging_entry.is_child = not staging_entry.is_parent

    staging_entry.save()
