# dictionary/tasks.py
import logging
from celery import shared_task
from django.core.cache import cache
from django.db import transaction
from rest_framework.exceptions import ValidationError

logger = logging.getLogger(__name__)

@shared_task(bind=True)
def process_staging_bulk_import(
    self,
    file_path,
    user_id,
    task_id=None
):
    """
    Celery task for processing bulk dictionary imports
    """
    from django.contrib.auth import get_user_model
    from .serializers import StagingEntryCreateSerializer
    import pandas as pd

    User = get_user_model()

    try:
        # Retrieve user
        user = User.objects.get(id=user_id)

        # Read Excel file
        df = pd.read_excel(file_path)

        # Prepare tracking variables
        import_results = {
            'total_entries': len(df),
            'successful_entries': 0,
            'failed_entries': [],
            'status': 'PROCESSING'
        }

        # Cache import results for tracking
        cache.set(f'import_task_{task_id}', import_results, timeout=3600)

        # Bulk import with transaction management
        with transaction.atomic():
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
                        serializer.save()
                        import_results['successful_entries'] += 1
                    else:
                        import_results['failed_entries'].append({
                            'row': index + 2,
                            'errors': serializer.errors
                        })

                except Exception as row_error:
                    import_results['failed_entries'].append({
                        'row': index + 2,
                        'errors': str(row_error)
                    })

                # Update cache periodically
                if index % 50 == 0:
                    cache.set(f'import_task_{task_id}', import_results, timeout=3600)

        # Final status update
        import_results['status'] = (
            'COMPLETED' if not import_results['failed_entries']
            else 'COMPLETED_WITH_ERRORS'
        )
        cache.set(f'import_task_{task_id}', import_results, timeout=3600)

        # Log import summary
        logger.info(f"Bulk Import Task {task_id} Summary: "
                    f"Total: {import_results['total_entries']}, "
                    f"Successful: {import_results['successful_entries']}, "
                    f"Failed: {len(import_results['failed_entries'])}")

        return import_results

    except Exception as e:
        # Comprehensive error handling
        error_details = {
            'error': str(e),
            'status': 'FAILED'
        }

        # Log the error
        logger.error(f"Bulk Import Task {task_id} Failed: {str(e)}")

        # Update cache with error
        cache.set(f'import_task_{task_id}', error_details, timeout=3600)

        # Raise the error for Celery to handle
        raise self.retry(exc=e, max_retries=3, countdown=60)
