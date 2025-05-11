# dictionary/views.py
from datetime import datetime
import json
import math
import threading
import time
import logging
from functools import wraps, reduce
import operator
import hashlib
import traceback
import uuid
import pandas as pd
import os
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.views import APIView
from rest_framework.exceptions import ValidationError as DRFValidationError
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.utils import timezone
from django.http import FileResponse
from django.core.cache import cache
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db.models import Q, Max, Case, When, Value, IntegerField, Prefetch

from users.models import User, ActivityLog
from .models import Dictionary, Staging, Bookmark, WordType, RelatedWord
from .serializers import (
    DictionaryEntrySerializer,
    BookmarkSerializer,
    StagingEntrySerializer,
    StagingEntryCreateSerializer,
)
from debug_utils import debug_error
from .tasks import process_staging_bulk_import_sync
from .utils import DictionaryTemplateGenerator, convert_to_khmer_date
from users.utils import log_activity
from dictionary import models

from dictionary import serializers

logger = logging.getLogger(__name__)

def process_word_relationships(word_entry):
    """
    Process word relationships based on the rules:
    - Single word: is_parent=True, is_child=False
    - Multiple words: Check if components exist, mark as children
    """
    # Split the word_en to check if it contains multiple words
    words = word_entry.word_en.split()

    if len(words) == 1:
        # Single word - mark as parent
        word_entry.is_parent = True
        word_entry.is_child = False
        word_entry.save()
        return

    # Multiple words - check if any exist in dictionary
    word_entry.is_parent = False

    # Look for potential parent words
    potential_parents = Dictionary.objects.filter(
        word_en__in=words,
        is_parent=True
    )

    if potential_parents.exists():
        # This word is a child of existing parent words
        word_entry.is_child = True
        word_entry.save()

        # Create relationships with parent words
        for parent in potential_parents:
            RelatedWord.objects.get_or_create(
                parent_word=parent,
                child_word=word_entry,
                defaults={'relationship_type': 'COMPOUND'}
            )
    else:
        # No parents found, this could be a new parent word
        word_entry.is_child = False
        word_entry.save()

def track_search_performance(func):
    @wraps(func)
    def wrapper(self, request, *args, **kwargs):
        start_time = time.time()
        try:
            response = func(self, request, *args, **kwargs)

            # Log performance metrics
            execution_time = time.time() - start_time
            logger.info("Search Performance: %s", {
                'query': request.query_params.get('query'),
                'language': request.query_params.get('language', 'ALL'),
                'execution_time_ms': execution_time * 1000,
                'result_count': len(response.data.get('results', [])) if hasattr(response, 'data') else 0,
                'total_results': response.data.get('total_results', 0) if hasattr(response, 'data') else 0
            })

            return response
        except Exception as e:
            logger.error("Search Error: %s", str(e))
            raise
    return wrapper

class SearchRateThrottle(UserRateThrottle):
    scope = 'search'

class DictionaryEntryListView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all approved dictionary entries with pagination and optimization",
        manual_parameters=[
            openapi.Parameter(
                'page',
                openapi.IN_QUERY,
                description="Page number for pagination",
                type=openapi.TYPE_INTEGER,
                default=1
            ),
            openapi.Parameter(
                'per_page',
                openapi.IN_QUERY,
                description="Number of entries per page",
                type=openapi.TYPE_INTEGER,
                default=25
            ),
            openapi.Parameter(
                'language',
                openapi.IN_QUERY,
                description="Filter entries by language (kh or en)",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'search',
                openapi.IN_QUERY,
                description="Search entries by word",
                type=openapi.TYPE_STRING
            )
        ],
        responses={
            200: openapi.Response(
                description='Successful retrieval of dictionary entries',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'entries': openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(type=openapi.TYPE_OBJECT)
                                ),
                                'total_entries': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'page': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'per_page': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'total_pages': openapi.Schema(type=openapi.TYPE_INTEGER)
                            }
                        )
                    }
                )
            )
        }
    )
    @debug_error
    def get(self, request):
        try:
            # Get query parameters with defaults
            page = max(1, int(request.query_params.get('page', 1)))
            per_page = max(1, int(request.query_params.get('per_page', 50)))
            language = request.query_params.get('language')
            search = request.query_params.get('search')

            # Base queryset with optimization
            entries_query = Dictionary.objects.filter(is_deleted=False).annotate(
                parent_priority=Case(
                    When(is_parent=True, then=Value(0)),
                    default=Value(1),
                    output_field=IntegerField()
                )
            ).order_by('parent_priority', 'id')

            # Apply language filter if provided
            if language:
                if language == 'kh':
                    entries_query = entries_query.filter(word_kh__isnull=False)
                elif language == 'en':
                    entries_query = entries_query.filter(word_en__isnull=False)

            # Apply search filter if provided
            if search:
                entries_query = entries_query.filter(
                    Q(word_kh__icontains=search) |
                    Q(word_en__icontains=search)
                )

            # Prefetch related words for parent entries
            entries_query = entries_query.prefetch_related(
                Prefetch(
                    'child_words',
                    queryset=RelatedWord.objects.select_related('child_word'),
                    to_attr='prefetched_child_words'
                )
            )

            # Calculate pagination
            total_entries = entries_query.count()
            total_pages = (total_entries + per_page - 1) // per_page

            # Apply pagination
            start = (page - 1) * per_page
            end = start + per_page
            entries = entries_query[start:end]

            # Serialize entries
            serializer = DictionaryEntrySerializer(
                entries,
                many=True,
                context={'request': request}
            )

            # Prepare response
            response_data = {
                'entries': serializer.data,
                'total_entries': total_entries,
                'page': page,
                'per_page': per_page,
                'total_pages': total_pages
            }

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Dictionary entries retrieved successfully',
                'data': response_data
            })

        except Exception as e:
            logger.error(f"Dictionary list error: {str(e)}", exc_info=True)
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'An error occurred while retrieving dictionary entries',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DictionaryEntryDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve a specific dictionary entry by ID",
        manual_parameters=[
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                description="ID of the dictionary entry",
                type=openapi.TYPE_INTEGER,
                required=True
            )
        ],
        responses={
            200: openapi.Response(
                description='Successful retrieval of dictionary entry',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                                'word_kh_type': openapi.Schema(type=openapi.TYPE_STRING),
                                'word_en_type': openapi.Schema(type=openapi.TYPE_STRING),
                                'word_kh_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                'word_en_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                'pronunciation_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                'pronunciation_en': openapi.Schema(type=openapi.TYPE_STRING),
                                'example_sentence_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                'example_sentence_en': openapi.Schema(type=openapi.TYPE_STRING),
                                'related_words': openapi.Schema(
                                    type=openapi.TYPE_OBJECT,
                                    properties={
                                        'parents': openapi.Schema(
                                            type=openapi.TYPE_ARRAY,
                                            items=openapi.Schema(
                                                type=openapi.TYPE_OBJECT,
                                                properties={
                                                    'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                                    'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                                                    'relationship_type': openapi.Schema(type=openapi.TYPE_STRING)
                                                }
                                            )
                                        ),
                                        'children': openapi.Schema(
                                            type=openapi.TYPE_ARRAY,
                                            items=openapi.Schema(
                                                type=openapi.TYPE_OBJECT,
                                                properties={
                                                    'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                                    'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                                                    'relationship_type': openapi.Schema(type=openapi.TYPE_STRING)
                                                }
                                            )
                                        )
                                    }
                                )
                            }
                        )
                    }
                )
            ),
            400: 'Bad Request',
            404: 'Entry Not Found'
        }
    )
    @debug_error
    def get(self, request):
        # Get the entry ID from query parameters
        entry_id = request.query_params.get('id')

        if not entry_id:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Entry ID is required',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Retrieve the dictionary entry with related words
            entry = Dictionary.objects.prefetch_related(
                Prefetch(
                    'child_words',
                    queryset=RelatedWord.objects.select_related('child_word'),
                    to_attr='prefetched_child_words'
                ),
                Prefetch(
                    'parent_words',
                    queryset=RelatedWord.objects.select_related('parent_word'),
                    to_attr='prefetched_parent_words'
                )
            ).get(id=entry_id)

            # Serialize the entry
            serializer = DictionaryEntrySerializer(
                entry,
                context={'request': request}
            )

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Dictionary entry retrieved successfully',
                'data': serializer.data
            })

        except Dictionary.DoesNotExist:
            return Response({
                'responseCode': status.HTTP_404_NOT_FOUND,
                'message': 'Dictionary entry not found',
                'data': None
            }, status=status.HTTP_404_NOT_FOUND)

class DictionarySearchView(APIView):
    permission_classes = [AllowAny]
    throttle_classes = [SearchRateThrottle, AnonRateThrottle]

    DEFAULT_SEARCH_FIELDS = ['word', 'definition', 'example_sentence']

    def get_cache_key(self, query, language, search_fields):
        key_components = [query, language, ','.join(search_fields)]
        return f"dict_search_{hashlib.md5(''.join(key_components).encode()).hexdigest()}"

    def build_search_query(self, query, search_fields, language):
        field_mapping = {
            'word': ['word_kh', 'word_en'],
            'definition': ['word_kh_definition', 'word_en_definition'],
            'example_sentence': ['example_sentence_kh', 'example_sentence_en']
        }

        search_conditions = []

        for field in search_fields:
            field_conditions = []

            if language in ['kh', 'ALL']:
                field_conditions.extend([
                    Q(**{f'{mapped_field}__icontains': query})
                    for mapped_field in field_mapping[field] if 'kh' in mapped_field
                ])

            if language in ['en', 'ALL']:
                field_conditions.extend([
                    Q(**{f'{mapped_field}__icontains': query})
                    for mapped_field in field_mapping[field] if 'en' in mapped_field
                ])

            if field_conditions:
                search_conditions.append(reduce(operator.or_, field_conditions))

        return reduce(operator.or_, search_conditions) if search_conditions else Q()

    @swagger_auto_schema(
        operation_description="Comprehensive Dictionary Search Endpoint",
        manual_parameters=[
            openapi.Parameter(
                name='query',
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_STRING,
                description='Search term (required)',
                required=True
            ),
            openapi.Parameter(
                name='language',
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_STRING,
                description='Language search direction',
                enum=['kh', 'en', 'ALL'],
                default='ALL'
            ),
            openapi.Parameter(
                name='search_fields',
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_ARRAY,
                items=openapi.Items(
                    type=openapi.TYPE_STRING,
                    enum=['word', 'definition', 'example_sentence']
                ),
                description='Fields to search (default: word, definition, example_sentence)',
                default=['word', 'definition', 'example_sentence']
            ),
            openapi.Parameter(
                name='page',
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_INTEGER,
                description='Page number for pagination',
                default=1
            ),
            openapi.Parameter(
                name='per_page',
                in_=openapi.IN_QUERY,
                type=openapi.TYPE_INTEGER,
                description='Number of results per page',
                default=25
            )
        ],
        responses={
            200: openapi.Response(
                description='Successful Search Results',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'results': openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(
                                        type=openapi.TYPE_OBJECT,
                                        properties={
                                            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                            'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_kh_type': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_en_type': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_kh_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_en_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                            'example_sentence_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                            'example_sentence_en': openapi.Schema(type=openapi.TYPE_STRING)
                                        }
                                    )
                                ),
                                'total_results': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'page': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'total_pages': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'search_query': openapi.Schema(type=openapi.TYPE_STRING),
                                'search_language': openapi.Schema(type=openapi.TYPE_STRING),
                                'search_fields': openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(type=openapi.TYPE_STRING)
                                )
                            }
                        )
                    }
                )
            ),
            400: openapi.Response(
                description='Bad Request',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            )
        }
    )
    @debug_error
    @track_search_performance

    def get(self, request):
        try:
            # Extract parameters
            query = request.query_params.get('query', '').strip()
            language = request.query_params.get('language', 'ALL')
            search_fields = request.query_params.getlist('search_fields') or self.DEFAULT_SEARCH_FIELDS
            page = max(1, int(request.query_params.get('page', 1)))
            per_page = max(1, int(request.query_params.get('per_page', 50)))

            # Validate input
            if not query:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Search query is required',
                    'data': {}
                }, status=status.HTTP_400_BAD_REQUEST)

            # Generate cache key
            cache_key = self.get_cache_key(query, language, search_fields)

            # Check cache
            cached_results = cache.get(cache_key)
            if cached_results:
                return Response(cached_results)

            # Build search query
            search_query = self.build_search_query(query, search_fields, language)

            # Perform search
            entries = Dictionary.objects.filter(search_query)

            # Pagination
            total_results = entries.count()
            total_pages = (total_results + per_page - 1) // per_page

            # Apply pagination
            start = (page - 1) * per_page
            end = start + per_page
            paginated_entries = entries[start:end]

            # Prepare response
            response_data = {
                'responseCode': status.HTTP_200_OK,
                'message': 'Dictionary search completed successfully',
                'data': {
                    'results': [
                        {
                            'id': entry.id,
                            'word_kh': entry.word_kh,
                            'word_en': entry.word_en,
                            'word_kh_type': entry.word_kh_type,
                            'word_en_type': entry.word_en_type,
                            'word_kh_definition': entry.word_kh_definition,
                            'word_en_definition': entry.word_en_definition,
                            # 'example_sentence_kh': entry.example_sentence_kh or '',
                            # 'example_sentence_en': entry.example_sentence_en or ''
                        }
                        for entry in paginated_entries
                    ],
                    'total_results': total_results,
                    'page': page,
                    'total_pages': total_pages,
                    'search_query': query,
                    'search_language': language,
                    'search_fields': search_fields
                }
            }

            # Cache the response
            cache.set(cache_key, response_data, timeout=3600)  # Cache for 1 hour

            return Response(response_data)

        except Exception as e:
            logger.error(f"Search Error: {str(e)}")
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Internal server error during search',
                'data': {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DictionaryDeleteView(APIView):
    permission_classes = [IsAuthenticated]  # Only SUPERUSER can drop entries

    @swagger_auto_schema(
        operation_description="Drop dictionary entries by specific ID(s) (SUPERUSER only)",
        manual_parameters=[
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                description="Comma-separated list of entry IDs to drop",
                type=openapi.TYPE_STRING,
                required=True
            )
        ],
        responses={
            200: openapi.Response(
                description='Entries successfully dropped',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'total_dropped': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'dropped_ids': openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(type=openapi.TYPE_INTEGER)
                                ),
                                'failed_ids': openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(type=openapi.TYPE_INTEGER)
                                )
                            }
                        )
                    }
                )
            ),
            400: 'Bad Request - Invalid ID format',
            403: 'Forbidden - Insufficient permissions',
            500: 'Internal Server Error'
        }
    )
    @debug_error
    def delete(self, request):
        # Check if user is SUPERUSER
        if request.user.role != 'SUPERUSER':
            return Response({
                'responseCode': status.HTTP_403_FORBIDDEN,
                'message': 'Only SUPERUSER can delete dictionary entries',
                'data': None
            }, status=status.HTTP_403_FORBIDDEN)

        try:
            # Get ID parameter
            id_param = request.query_params.get('id')
            # Validate ID parameter
            if not id_param:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'ID parameter is required',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)
            # Parse IDs, handling both comma-separated and single ID
            try:
                # Split and convert to integers, removing any whitespace
                ids = [int(id.strip()) for id in id_param.split(',') if id.strip()]
            except ValueError:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid ID format. Must be integer or comma-separated integers',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)
            # Prepare lists to track dropped and failed entries
            dropped_ids = []
            failed_ids = []
            # Process each ID
            for entry_id in ids:
                try:
                    # Retrieve the dictionary entry
                    entry = Dictionary.objects.get(id=entry_id, is_deleted=False)
                    # Perform soft delete
                    entry.soft_delete(user=request.user)
                    dropped_ids.append(entry_id)
                except Dictionary.DoesNotExist:
                    # Track IDs that don't exist
                    failed_ids.append(entry_id)
                except Exception as e:
                    # Log any unexpected errors
                    logger.error(f"Error dropping entry {entry_id}: {str(e)}")
                    failed_ids.append(entry_id)
            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': f'{len(dropped_ids)} dictionary entries dropped',
                'data': {
                    'total_dropped': len(dropped_ids),
                    'dropped_ids': dropped_ids,
                    'failed_ids': failed_ids
                }
            })
        except Exception as e:
            logger.error(f"Dictionary drop error: {str(e)}", exc_info=True)
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Failed to drop dictionary entries',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DictionaryUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update dictionary entry (SUPERUSER only)",
        manual_parameters=[
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                description="ID of the dictionary entry to update",
                type=openapi.TYPE_INTEGER,
                required=True
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                'word_kh_type': openapi.Schema(type=openapi.TYPE_STRING),
                'word_en_type': openapi.Schema(type=openapi.TYPE_STRING),
                'word_kh_definition': openapi.Schema(type=openapi.TYPE_STRING),
                'word_en_definition': openapi.Schema(type=openapi.TYPE_STRING),
                'pronunciation_kh': openapi.Schema(type=openapi.TYPE_STRING),
                'pronunciation_en': openapi.Schema(type=openapi.TYPE_STRING),
                'example_sentence_kh': openapi.Schema(type=openapi.TYPE_STRING),
                'example_sentence_en': openapi.Schema(type=openapi.TYPE_STRING)
            }
        ),
        responses={
            200: openapi.Response(
                description='Dictionary entry updated successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            ),
            400: 'Bad Request',
            403: 'Forbidden - Only SUPERUSER can update dictionary entries',
            404: 'Dictionary entry not found'
        }
    )
    @debug_error
    def put(self, request):
        # Check if user is SUPERUSER
        if request.user.role != 'SUPERUSER':
            return Response({
                'responseCode': status.HTTP_403_FORBIDDEN,
                'message': 'Only SUPERUSER can update dictionary entries',
                'data': None
            }, status=status.HTTP_403_FORBIDDEN)

        # Get the entry ID from query parameters
        entry_id = request.query_params.get('id')

        if not entry_id:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Dictionary entry ID is required',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Retrieve the dictionary entry
            dictionary_entry = Dictionary.objects.get(id=entry_id, is_deleted=False)

            # Create a serializer for the dictionary entry
            serializer = DictionaryEntrySerializer(
                dictionary_entry,
                data=request.data,
                partial=True
            )

            if serializer.is_valid():
                # Save the updated entry
                updated_entry = serializer.save(
                    updated_at=timezone.now(),
                    updated_by=request.user
                )

                # Log the activity
                log_activity(
                    admin_user=request.user,
                    action='DICTIONARY_UPDATE',
                    word_kh=updated_entry.word_kh,
                    word_en=updated_entry.word_en
                )

                return Response({
                    'responseCode': status.HTTP_200_OK,
                    'message': 'Dictionary entry updated successfully',
                    'data': serializer.data
                })
            else:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Validation error',
                    'errors': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

        except Dictionary.DoesNotExist:
            return Response({
                'responseCode': status.HTTP_404_NOT_FOUND,
                'message': 'Dictionary entry not found',
                'data': None
            }, status=status.HTTP_404_NOT_FOUND)

def generate_next_index():
    """
    Generate the next sequential index for Dictionary entries
    """
    try:
        # Get the maximum current index, default to 0 if no entries exist
        max_index = Dictionary.objects.aggregate(Max('index'))['index__max'] or 0
        return max_index + 1
    except Exception as e:
        logger.error(f"Error generating index: {e}")
        # Fallback mechanism
        return Dictionary.objects.count() + 1

class StagingEntryListView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List Staging Entries with Pagination",
        manual_parameters=[
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                description="User ID to filter entries",
                type=openapi.TYPE_INTEGER,
                required=False
            ),
            openapi.Parameter(
                'page',
                openapi.IN_QUERY,
                description="Page number",
                type=openapi.TYPE_INTEGER,
                default=1
            ),
            openapi.Parameter(
                'per_page',
                openapi.IN_QUERY,
                description="Entries per page",
                type=openapi.TYPE_INTEGER,
                default=50
            ),
            openapi.Parameter(
                'review_status',
                openapi.IN_QUERY,
                description="Filter by review status",
                type=openapi.TYPE_STRING,
                required=False
            )
        ]
    )
    def get(self, request):
        # Get query parameters
        user_id = request.query_params.get('id')

        # Validate and convert page and per_page
        try:
            page = max(1, int(request.query_params.get('page', 1)))
            per_page = max(1, int(request.query_params.get('per_page', 50)))
            review_status = request.query_params.get('review_status')
        except ValueError:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Invalid page or per_page parameter',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        # When no ID is provided, only Admin/SuperUser can access all entries
        if not user_id:
            if request.user.role not in ['ADMIN', 'SUPERUSER']:
                return Response({
                    'responseCode': status.HTTP_403_FORBIDDEN,
                    'message': 'Only Admin/SuperUser can view all staging entries',
                    'data': None
                }, status=status.HTTP_403_FORBIDDEN)

            # Fetch all staging entries for Admin/SuperUser
            staging_entries = Staging.objects.all().order_by('-created_at')

        else:
            # Convert user_id to integer
            try:
                user_id = int(user_id)
            except ValueError:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid user ID format',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check user permissions for specific user ID
            if (user_id != request.user.id and
                request.user.role not in ['ADMIN', 'SUPERUSER']):
                return Response({
                    'responseCode': status.HTTP_403_FORBIDDEN,
                    'message': 'You do not have permission to view this user\'s staging entries',
                    'data': None
                }, status=status.HTTP_403_FORBIDDEN)

            # Fetch staging entries for the specific user
            staging_entries = Staging.objects.filter(created_by_id=user_id).order_by('-created_at')

            # Apply review_status filter
            if review_status:
                entries = entries.filter(review_status=review_status)

        # Manual Pagination
        total_entries = staging_entries.count()
        total_pages = (total_entries + per_page - 1) // per_page

        # Check if requested page is out of range
        if page > total_pages and total_pages > 0:
            return Response({
                'responseCode': status.HTTP_404_NOT_FOUND,
                'message': 'Page number out of range',
                'data': None
            }, status=status.HTTP_404_NOT_FOUND)

        # Apply pagination
        start = (page - 1) * per_page
        end = start + per_page
        paginated_entries = staging_entries[start:end]

        # Serialize the entries
        serializer = StagingEntrySerializer(paginated_entries, many=True)

        return Response({
            'responseCode': status.HTTP_200_OK,
            'message': 'Staging entries retrieved successfully',
            'data': {
                'entries': serializer.data,
                'total_entries': total_entries,
                'total_pages': total_pages,
                'current_page': page,
                'per_page': per_page
            }
        })

class StagingEntryCreateView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Create a new staging entry for dictionary",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=[
                'word_kh',
                'word_kh_type',
                'word_kh_definition',
                'word_en',
                'word_en_type',
                'word_en_definition'
            ],
            properties={
                'word_kh': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Khmer word"
                ),
                'word_kh_type': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Khmer word type",
                    enum=[choice[0] for choice in WordType.WORD_TYPE_CHOICES_KH]
                ),
                'word_kh_definition': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Definition of the Khmer word"
                ),
                'word_en': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="English word"
                ),
                'word_en_type': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="English word type",
                    enum=[choice[0] for choice in WordType.WORD_TYPE_CHOICES_EN]
                ),
                'word_en_definition': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Definition of the English word"
                ),
                'pronunciation_kh': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Pronunciation of the Khmer word (optional)"
                ),
                'pronunciation_en': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Pronunciation of the English word (optional)"
                ),
                'example_sentence_kh': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Example sentence in Khmer (optional)"
                ),
                'example_sentence_en': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Example sentence in English (optional)"
                )
            }
        ),
        responses={
            201: openapi.Response(
                description='Entry created successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            ),
            400: 'Validation Error'
        }
    )
    @debug_error
    def post(self, request):
        # Check if the user is an ADMIN or SUPERUSER
        is_admin_or_superuser = request.user.role in ['ADMIN', 'SUPERUSER']

        # Prepare serializer
        serializer = StagingEntryCreateSerializer(
            data=request.data,
            context={'request': request}
        )

        if serializer.is_valid():
            # Prepare data for staging entry
            staging_data = serializer.validated_data.copy()

            # Check for existing entry in staging
            existing_staging_entry = Staging.objects.filter(
                Q(word_en=staging_data.get('word_en')) &
                Q(word_kh=staging_data.get('word_kh'))
            ).first()

            if existing_staging_entry:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'An entry with this word already exists in staging',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Determine review status and related fields
            if is_admin_or_superuser:
                # For ADMIN/SUPERUSER: Automatically approve
                review_status = 'APPROVED'
                reviewed_by = request.user
                reviewed_at = timezone.now()
            else:
                # For regular users: Default to PENDING
                review_status = 'PENDING'
                reviewed_by = None
                reviewed_at = None

            # Create staging entry
            try:

                # Create staging entry
                staging_entry = Staging.objects.create(
                    **staging_data,
                    created_by=request.user,
                    review_status=review_status,
                    reviewed_by=reviewed_by,
                    reviewed_at=reviewed_at,
                    is_parent=False,  # Initial state
                    is_child=False   # Initial state
                )

                # Process word relationships for staging entry
                self._process_staging_word_relationships(staging_entry)

                # If ADMIN/SUPERUSER, also create in Dictionary
                if is_admin_or_superuser:
                    dictionary_entry = self._create_dictionary_entry_from_staging(
                        staging_entry,
                        request.user
                    )

                    # Log the activity using username_kh
                    log_activity(
                        admin_user=request.user,
                        action='STAGING_CREATE',
                        word_kh=staging_entry.word_kh,
                        word_en=staging_entry.word_en
                    )

                    return Response({
                        'responseCode': status.HTTP_201_CREATED,
                        'message': 'Dictionary entry created successfully',
                        'data': None
                    }, status=status.HTTP_201_CREATED)

                # Log the activity using username_kh
                log_activity(
                    admin_user=request.user,
                    action='STAGING_CREATE',
                    word_kh=staging_entry.word_kh,
                    word_en=staging_entry.word_en
                )

                # For non-admin users
                return Response({
                    'responseCode': status.HTTP_201_CREATED,
                    'message': 'Staging entry created successfully',
                    'data': {
                        'id': staging_entry.id,
                        'review_status': review_status
                    }
                }, status=status.HTTP_201_CREATED)

            except Exception as e:
                return Response({
                    'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                    'message': f'Error creating entry: {str(e)}',
                    'data': None
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        # Validation errors
        return Response({
            'responseCode': status.HTTP_400_BAD_REQUEST,
            'message': 'Invalid data',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def _process_staging_word_relationships(self, staging_entry):
        """
        Process word relationships for staging entry
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

        staging_entry.save()

    def _create_dictionary_entry_from_staging(self, staging_entry, user):
        """
        Create Dictionary entry from Staging entry for ADMIN/SUPERUSER
        """
        # Generate next index
        next_index = generate_next_index()

        # Create Dictionary entry
        dictionary_entry = Dictionary.objects.create(
            index=next_index,
            word_kh=staging_entry.word_kh,
            word_en=staging_entry.word_en,
            word_kh_type=staging_entry.word_kh_type,
            word_en_type=staging_entry.word_en_type,
            word_kh_definition=staging_entry.word_kh_definition,
            word_en_definition=staging_entry.word_en_definition,
            pronunciation_kh=staging_entry.pronunciation_kh,
            pronunciation_en=staging_entry.pronunciation_en,
            example_sentence_kh=staging_entry.example_sentence_kh,
            example_sentence_en=staging_entry.example_sentence_en,
            created_by=user,
            is_parent=staging_entry.is_parent,
            is_child=staging_entry.is_child
        )

        # Process word relationships
        process_word_relationships(dictionary_entry)

        return dictionary_entry

    def _generate_unique_index(self):
        """Generate a unique index for Dictionary entries"""
        max_index = Dictionary.objects.aggregate(Max('index'))['index__max'] or 0
        return max_index + 1

class StagingEntryApproveView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Approve a staging entry",
        manual_parameters=[
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                description="ID of the staging entry to approve",
                type=openapi.TYPE_INTEGER,
                required=True
            )
        ],
        responses={
            200: 'Successfully approved',
            403: 'Forbidden',
            404: 'Not found'
        }
    )
    @debug_error
    def post(self, request):
        try:
            # Get the entry ID from query parameters
            entry_id = request.query_params.get('id')

            if not entry_id:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Entry ID is required',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Retrieve the staging entry
            staging_entry = Staging.objects.get(id=entry_id)

            # Check permissions
            if request.user.role not in ['ADMIN', 'SUPERUSER']:
                return Response({
                    'responseCode': status.HTTP_403_FORBIDDEN,
                    'message': 'You are not authorized to approve this entry',
                    'data': None
                }, status=status.HTTP_403_FORBIDDEN)

            # Create Dictionary entry
            dictionary_entry = self._create_dictionary_entry_from_staging(staging_entry, request.user)

            # Process word relationships
            self._process_word_relationships(dictionary_entry, staging_entry)

            # Update staging entry status
            staging_entry.review_status = 'APPROVED'
            staging_entry.reviewed_by = request.user
            staging_entry.reviewed_at = timezone.now()
            staging_entry.save()

            # Log the activity
            log_activity(
                admin_user=request.user,
                action='STAGING_APPROVE',
                word_kh=staging_entry.word_kh,
                word_en=staging_entry.word_en
            )

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Staging entry approved successfully',
                'data': {
                    'id': dictionary_entry.id,
                    'word_kh': dictionary_entry.word_kh,
                    'word_en': dictionary_entry.word_en
                }
            })

        except Staging.DoesNotExist:
            return Response({
                'responseCode': status.HTTP_404_NOT_FOUND,
                'message': 'Staging entry not found',
                'data': None
            }, status=status.HTTP_404_NOT_FOUND)

    def _process_word_relationships(self, dictionary_entry, staging_entry):
        """
        Process word relationships for dictionary entries
        """
        # Split words for both Khmer and English
        kh_words = staging_entry.word_kh.split()
        en_words = staging_entry.word_en.split()

        # Process English words relationships
        if len(en_words) > 1:
            # Find potential parent words
            for word in en_words[:-1]:  # Exclude the last word
                parent_word = Dictionary.objects.filter(
                    word_en=word,
                    is_parent=True
                ).first()

                if parent_word:
                    # Create RelatedWord entry
                    RelatedWord.objects.get_or_create(
                        parent_word=parent_word,
                        child_word=dictionary_entry,
                        defaults={
                            'relationship_type': 'COMPOUND'
                        }
                    )

        # Process Khmer words relationships
        if len(kh_words) > 1:
            for word in kh_words[:-1]:  # Exclude the last word
                parent_word = Dictionary.objects.filter(
                    word_kh=word,
                    is_parent=True
                ).first()

                if parent_word:
                    # Create RelatedWord entry
                    RelatedWord.objects.get_or_create(
                        parent_word=parent_word,
                        child_word=dictionary_entry,
                        defaults={
                            'relationship_type': 'COMPOUND'
                        }
                    )

    def _create_dictionary_entry_from_staging(self, staging_entry, user):
        """
        Create a dictionary entry from a staging entry
        """
        # Generate unique index
        max_index = Dictionary.objects.aggregate(Max('index'))['index__max'] or 0
        new_index = max_index + 1

        # Create new dictionary entry
        new_word = Dictionary.objects.create(
            word_kh=staging_entry.word_kh,
            word_en=staging_entry.word_en,
            word_kh_type=staging_entry.word_kh_type,
            word_en_type=staging_entry.word_en_type,
            word_kh_definition=staging_entry.word_kh_definition,
            word_en_definition=staging_entry.word_en_definition,
            pronunciation_kh=staging_entry.pronunciation_kh,
            pronunciation_en=staging_entry.pronunciation_en,
            example_sentence_kh=staging_entry.example_sentence_kh,
            example_sentence_en=staging_entry.example_sentence_en,
            created_by=user,
            index=new_index
        )

        # Determine parent/child status
        words = staging_entry.word_en.split()
        full_phrase = staging_entry.word_en

        if len(words) == 1:
            new_word.is_parent = True
            new_word.is_child = False
        elif staging_entry.is_child:
            new_word.is_parent = False
            new_word.is_child = True

        new_word.save()

        return new_word

    def _create_dictionary_entry_from_staging(self, staging_entry, user):
        """
        Create Dictionary entry from Staging entry

        :param staging_entry: Staging entry to convert
        :param user: User creating the dictionary entry
        :return: Created Dictionary entry
        """
        # Generate next index
        next_index = self._generate_unique_index()

        # Determine parent-child status
        is_parent = self._determine_parent_status(staging_entry)
        is_child = not is_parent

        # Create Dictionary entry
        dictionary_entry = Dictionary.objects.create(
            index=next_index,
            word_kh=staging_entry.word_kh,
            word_en=staging_entry.word_en,
            word_kh_type=staging_entry.word_kh_type,
            word_en_type=staging_entry.word_en_type,
            word_kh_definition=staging_entry.word_kh_definition,
            word_en_definition=staging_entry.word_en_definition,
            pronunciation_kh=staging_entry.pronunciation_kh,
            pronunciation_en=staging_entry.pronunciation_en,
            example_sentence_kh=staging_entry.example_sentence_kh,
            example_sentence_en=staging_entry.example_sentence_en,
            created_by=user,
            is_parent=is_parent,
            is_child=is_child
        )

        return dictionary_entry

    def _generate_unique_index(self):
        """
        Generate a unique index for Dictionary entries

        :return: Next unique index
        """
        max_index = Dictionary.objects.aggregate(Max('index'))['index__max'] or 0
        return max_index + 1

    def _determine_parent_status(self, staging_entry):
        """
        Determine if the entry should be marked as a parent word

        :param staging_entry: Staging entry to check
        :return: Boolean indicating if the entry is a parent word
        """
        # Split words to check complexity
        words = staging_entry.word_en.split()

        # Single word scenario
        if len(words) == 1:
            return True

        # Multi-word scenario
        # Check if any of the words are existing parent words
        existing_parent_words = Dictionary.objects.filter(
            word_en__in=words,
            is_parent=True
        )

        # If no existing parent words found, this could be a parent
        return not existing_parent_words.exists()

class StagingEntryRejectView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Reject a staging entry",
        manual_parameters=[
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                description="ID of the staging entry to reject",
                type=openapi.TYPE_INTEGER,
                required=True
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['reason'],
            properties={
                'reason': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Reason for rejecting the entry',
                    minLength=10,  # Minimum length to ensure meaningful reason
                    maxLength=500  # Optional: set a maximum length
                )
            }
        ),
        responses={
            200: 'Successfully rejected',
            400: 'Invalid reason',
            403: 'Forbidden',
            404: 'Not found'
        }
    )
    @debug_error
    def post(self, request):
        # Get the entry ID from query parameters
        entry_id = request.query_params.get('id')

        # Validate entry ID
        if not entry_id:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Entry ID is required',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        # Extract and validate rejection reason
        reason = request.data.get('reason', '').strip()
        if not reason:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Rejection reason is required and cannot be empty',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        # Validate reason length
        if len(reason) < 10:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Rejection reason must be at least 10 characters long',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Retrieve the staging entry
            staging_entry = Staging.objects.get(id=entry_id)

            # Check permissions
            # Both ADMIN and SUPERUSER can reject entries
            if request.user.role not in ['ADMIN', 'SUPERUSER']:
                return Response({
                    'responseCode': status.HTTP_403_FORBIDDEN,
                    'message': 'You are not authorized to reject this entry',
                    'data': None
                }, status=status.HTTP_403_FORBIDDEN)

            # Update staging entry status
            staging_entry.review_status = 'REJECTED'
            staging_entry.reviewed_by = request.user
            staging_entry.reviewed_at = timezone.now()
            staging_entry.rejection_reason = reason
            staging_entry.save()

            # Log the activity
            log_activity(
                admin_user=request.user,
                action='STAGING_REJECT',
                word_kh=staging_entry.word_kh,
                word_en=staging_entry.word_en
            )

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Staging entry rejected successfully',
                'data': {
                    'staging_id': staging_entry.id,
                    'review_status': staging_entry.review_status,
                    'rejection_reason': reason
                }
            })

        except Staging.DoesNotExist:
            return Response({
                'responseCode': status.HTTP_404_NOT_FOUND,
                'message': 'Staging entry not found',
                'data': None
            }, status=status.HTTP_404_NOT_FOUND)

class StagingEntryDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve details of a specific staging entry",
        manual_parameters=[
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                description="ID of the staging entry",
                type=openapi.TYPE_INTEGER,
                required=True
            )
        ],
        responses={
            200: openapi.Response(
                description='Successful retrieval of staging entry details',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                                'word_kh_type': openapi.Schema(type=openapi.TYPE_STRING),
                                'word_en_type': openapi.Schema(type=openapi.TYPE_STRING),
                                'word_kh_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                'word_en_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                'pronunciation_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                'pronunciation_en': openapi.Schema(type=openapi.TYPE_STRING),
                                'example_sentence_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                'example_sentence_en': openapi.Schema(type=openapi.TYPE_STRING),
                                'created_by': openapi.Schema(type=openapi.TYPE_STRING),
                                'created_at': openapi.Schema(type=openapi.TYPE_STRING, format='date-time'),
                                'review_status': openapi.Schema(type=openapi.TYPE_STRING),
                                'reviewed_by': openapi.Schema(type=openapi.TYPE_STRING),
                                'reviewed_at': openapi.Schema(type=openapi.TYPE_STRING, format='date-time'),
                                'rejection_reason': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            ),
            400: 'Bad Request',
            403: 'Forbidden',
            404: 'Not Found'
        }
    )
    @debug_error
    def get(self, request):
        # Get the entry ID from query parameters
        entry_id = request.query_params.get('id')

        if not entry_id:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Entry ID is required',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Retrieve the staging entry
            staging_entry = Staging.objects.select_related(
                'created_by',
                'reviewed_by',
            ).get(id=entry_id)

            # Check if user is authorized to view the entry
            # ADMIN can view any entry
            # SUPERUSER can view any entry
            # Regular users can only view their own entries
            is_authorized = (
                request.user.role in ['ADMIN', 'SUPERUSER'] or
                staging_entry.created_by == request.user
            )

            if not is_authorized:
                return Response({
                    'responseCode': status.HTTP_403_FORBIDDEN,
                    'message': 'You are not authorized to view this entry',
                    'data': None
                }, status=status.HTTP_403_FORBIDDEN)

            # Serialize the entry
            serializer = StagingEntrySerializer(
                staging_entry,
                context={'request': request}
            )

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Staging entry retrieved successfully',
                'data': serializer.data
            })

        except Staging.DoesNotExist:
            return Response({
                'responseCode': status.HTTP_404_NOT_FOUND,
                'message': 'Staging entry not found',
                'data': None
            }, status=status.HTTP_404_NOT_FOUND)

class StagingEntryUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update Staging Entry",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                'word_kh_type': openapi.Schema(type=openapi.TYPE_STRING),
                'word_en_type': openapi.Schema(type=openapi.TYPE_STRING),
                'word_kh_definition': openapi.Schema(type=openapi.TYPE_STRING),
                'word_en_definition': openapi.Schema(type=openapi.TYPE_STRING),
                'pronunciation_kh': openapi.Schema(type=openapi.TYPE_STRING),
                'pronunciation_en': openapi.Schema(type=openapi.TYPE_STRING),
                'example_sentence_kh': openapi.Schema(type=openapi.TYPE_STRING),
                'example_sentence_en': openapi.Schema(type=openapi.TYPE_STRING)
            }
        ),
        responses={
            200: openapi.Response(
                description='Staging Entry Updated Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            ),
            400: 'Validation Error',
            403: 'Unauthorized'
        }
    )
    @debug_error
    def put(self, request):
        try:
            # Get the staging entry ID from query parameters
            staging_id = request.query_params.get('id')

            # Validate staging ID
            if not staging_id:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Staging entry ID is required',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Retrieve the staging entry
            try:
                staging_entry = Staging.objects.get(id=staging_id)
            except Staging.DoesNotExist:
                return Response({
                    'responseCode': status.HTTP_404_NOT_FOUND,
                    'message': 'Staging entry not found',
                    'data': None
                }, status=status.HTTP_404_NOT_FOUND)

            # Prepare update data
            update_data = {}
            changed_fields = []

            # Fields to check for updates
            fields_to_check = [
                'word_kh', 'word_en',
                'word_kh_type', 'word_en_type',
                'word_kh_definition', 'word_en_definition',
                'pronunciation_kh', 'pronunciation_en',
                'example_sentence_kh', 'example_sentence_en'
            ]

            # Check each field for changes
            for field in fields_to_check:
                if field in request.data:
                    current_value = getattr(staging_entry, field, None)
                    new_value = request.data[field]

                    # Compare values, handling potential None/empty string cases
                    if (str(current_value or '') != str(new_value or '')):
                        update_data[field] = new_value
                        changed_fields.append(field)

            # Check if any changes were detected
            if not update_data:
                return Response({
                    'responseCode': status.HTTP_200_OK,
                    'message': 'No changes detected',
                    'data': None
                }, status=status.HTTP_200_OK)

            # Validate the update
            serializer = StagingEntrySerializer(
                staging_entry,
                data=update_data,
                partial=True,
                context={'request': request}
            )

            if serializer.is_valid():
                # Save the updated entry
                updated_entry = serializer.save()

                # Log the activity
                log_activity(
                    admin_user=request.user,
                    action='STAGING_UPDATE',
                    word_kh=updated_entry.word_kh,
                    word_en=updated_entry.word_en,
                    # action_details={
                    #     'changed_fields': changed_fields,
                    #     'staging_entry_id': updated_entry.id
                    # }
                )

                return Response({
                    'responseCode': status.HTTP_200_OK,
                    'message': 'Staging entry updated successfully',
                    'data': {
                        'changed_fields': changed_fields,
                        'updated_entry': StagingEntrySerializer(updated_entry).data
                    }
                }, status=status.HTTP_200_OK)

            # Handle validation errors
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Validation error',
                'data': serializer.errors
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Update failed',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class StagingEntryDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Delete a staging entry",
        manual_parameters=[
            openapi.Parameter(
                'id',
                openapi.IN_QUERY,
                description="ID of the staging entry to delete",
                type=openapi.TYPE_INTEGER,
                required=True
            )
        ],
        responses={
            200: 'Successfully deleted',
            403: 'Forbidden',
            404: 'Not found'
        }
    )
    @debug_error
    def delete(self, request):
        # Get the entry ID from query parameters
        entry_id = request.query_params.get('id')

        if not entry_id:
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Entry ID is required',
                'data': None
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Retrieve the staging entry
            staging_entry = Staging.objects.get(id=entry_id)

            # Check permissions
            # Only SUPERUSER can delete any entry
            # ADMIN and regular users can only delete their own entries
            if request.user.role != 'SUPERUSER' and staging_entry.created_by != request.user:
                return Response({
                    'responseCode': status.HTTP_403_FORBIDDEN,
                    'message': 'You are not authorized to delete this entry',
                    'data': None
                }, status=status.HTTP_403_FORBIDDEN)

            # Store word details for logging before deletion
            word_kh = staging_entry.word_kh
            word_en = staging_entry.word_en

            # Delete the entry
            staging_entry.delete()

            # Log the activity
            log_activity(
                admin_user=request.user,
                action='STAGING_DELETE',
                word_kh=word_kh,
                word_en=word_en
            )

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Staging entry deleted successfully',
                'data': None
            })

        except Staging.DoesNotExist:
            return Response({
                'responseCode': status.HTTP_404_NOT_FOUND,
                'message': 'Staging entry not found',
                'data': None
            }, status=status.HTTP_404_NOT_FOUND)


class BookmarkRateThrottle(UserRateThrottle):
    """
    Custom rate throttle to handle multiple device access
    """
    def get_cache_key(self, request, view):
        # Use device ID instead of user ID for rate limiting
        device_id = request.headers.get('X-Device-ID')
        return f'throttle_device_{device_id}'

class StagingBulkImportView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated]

    # Column name mapping for Khmer headers
    COLUMN_NAME_MAPPING = {
        'ល.រ': 'id',
        'ពាក្យខ្មែរ': 'word_kh',
        'ថ្នាក់ពាក្យខ្មែរ': 'word_kh_type',
        'និយមន័យ': 'word_kh_definition',
        'ពាក្យអង់គ្លេស': 'word_en',
        'ថ្នាក់ពាក្យអង់គ្លេស': 'word_en_type',
        'និយមន័យអង់គ្លេស': 'word_en_definition',
        'ការបញ្ចេញសំឡេងខ្មែរ': 'pronunciation_kh',
        'ការបញ្ចេញសំឡេងអង់គ្លេស': 'pronunciation_en',
        'ឧទាហរណ៍ខ្មែរ': 'example_sentence_kh',
        'ឧទាហរណ៍អង់គ្លេស': 'example_sentence_en'
    }

    # Expected columns in the correct order
    EXPECTED_COLUMNS = [
        'id', 'word_kh', 'word_kh_type', 'word_kh_definition',
        'word_en', 'word_en_type', 'word_en_definition',
        'pronunciation_kh', 'pronunciation_en',
        'example_sentence_kh', 'example_sentence_en'
    ]

    @swagger_auto_schema(
        operation_description="Bulk import dictionary entries via Excel",
        consumes=['multipart/form-data'],
        manual_parameters=[
            openapi.Parameter(
                name='file',
                in_=openapi.IN_FORM,
                type=openapi.TYPE_FILE,
                required=True,
                description="Excel file (.xlsx) with dictionary entries"
            )
        ],
        responses={
            200: openapi.Response(
                description='Successful import of dictionary entries',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'task_id': openapi.Schema(type=openapi.TYPE_STRING),
                        'activity_log_id': openapi.Schema(type=openapi.TYPE_INTEGER)
                    }
                )
            ),
            400: 'Invalid File or Data'
        }
    )
    @debug_error
    def post(self, request):
        try:
            # Validate file upload
            if 'file' not in request.FILES:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'No file uploaded',
                    'data': {'error': 'File is required for bulk import'}
                }, status=status.HTTP_400_BAD_REQUEST)

            excel_file = request.FILES['file']

            # Validate file type
            if not excel_file.name.endswith(('.xlsx', '.xls')):
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid file type',
                    'data': {'error': 'Please upload an Excel file (.xlsx or .xls)'}
                }, status=status.HTTP_400_BAD_REQUEST)

            # Save temporary file
            temp_file_path = os.path.join(
                settings.MEDIA_ROOT,
                'temp_imports',
                f'{uuid.uuid4()}_{excel_file.name}'
            )
            os.makedirs(os.path.dirname(temp_file_path), exist_ok=True)

            with open(temp_file_path, 'wb+') as destination:
                for chunk in excel_file.chunks():
                    destination.write(chunk)

            # Read Excel file
            try:
                df = pd.read_excel(temp_file_path)
                df.rename(columns=self.COLUMN_NAME_MAPPING, inplace=True)
            except Exception as read_error:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Error reading Excel file',
                    'data': {
                        'total_entries': 1,
                        'successful_entries': 0,
                        'failed_entries': [{
                            'row': 1,
                            'word_kh': '',
                            'word_en': '',
                            'errors': {
                                'non_field_errors': [str(read_error)]
                            }
                        }]
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

            # Validate column structure
            if list(df.columns) != self.EXPECTED_COLUMNS:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid column structure',
                    'data': {
                        'total_entries': 1,
                        'successful_entries': 0,
                        'failed_entries': [{
                            'row': 1,
                            'word_kh': '',
                            'word_en': '',
                            'errors': {
                                'non_field_errors': [
                                    'Column names do not match the template',
                                    f'Expected columns: {self.EXPECTED_COLUMNS}',
                                    f'Actual columns: {list(df.columns)}'
                                ]
                            }
                        }]
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

            # Prepare results tracking
            total_entries = len(df)
            successful_entries = 0
            failed_entries = []

            # Process each row
            for index, row in df.iterrows():
                try:
                    # Prepare data for serializer
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
                        context={'request': request}
                    )

                    if not serializer.is_valid():
                        # Collect validation errors in the specified format
                        failed_entry = {
                            'row': index + 1,  # Excel rows start at 1, add header
                            'word_kh': row['word_kh'],
                            'word_en': row['word_en'],
                            'errors': serializer.errors
                        }
                        failed_entries.append(failed_entry)
                    else:
                        # Save the staging entry
                        serializer.save()
                        successful_entries += 1

                except Exception as entry_error:
                    # Catch any unexpected errors during entry processing
                    failed_entry = {
                        'row': index + 1,
                        'word_kh': row['word_kh'],
                        'word_en': row['word_en'],
                        'errors': {
                            'non_field_errors': [str(entry_error)]
                        }
                    }
                    failed_entries.append(failed_entry)

            # If there are any failed entries, return validation failed response
            if failed_entries:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Validation failed',
                    'data': {
                        'total_entries': total_entries,
                        'successful_entries': successful_entries,
                        'failed_entries': failed_entries
                    }
                }, status=status.HTTP_400_BAD_REQUEST)

            # Successful import
            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Dictionary entries imported successfully',
                'data': {
                    'total_entries': total_entries,
                    'successful_entries': successful_entries,
                    'failed_entries': []
                }
            }, status=status.HTTP_200_OK)

        except Exception as e:
            # Handle any unexpected errors
            return Response({
                'responseCode': status.HTTP_400_BAD_REQUEST,
                'message': 'Validation failed',
                'data': {
                    'total_entries': 1,
                    'successful_entries': 0,
                    'failed_entries': [{
                        'row': 1,
                        'word_kh': '',
                        'word_en': '',
                        'errors': {
                            'non_field_errors': [str(e)]
                        }
                    }]
                }
            }, status=status.HTTP_400_BAD_REQUEST)

    def process_staging_bulk_import_local(self, file_path, user, activity_log):
        """
        Local synchronous processing method for bulk import
        Completely offline and does not rely on any network resources
        """
        # Read Excel file
        df = pd.read_excel(file_path)
        df.rename(columns=self.COLUMN_NAME_MAPPING, inplace=True)

        # Prepare results tracking
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
                    # Save staging entry
                    staging_entry = serializer.save(created_by=user)
                    import_results['successful_entries'] += 1

                    # Optional: Process word relationships for admin/superuser
                    if user.role in ['ADMIN', 'SUPERUSER']:
                        # Change this line to match the method name in the class
                        self._process_staging_word_relationships(staging_entry)
                else:
                    import_results['failed_entries'].append({
                        'row': index + 1,
                        'word_kh': row['word_kh'],
                        'word_en': row['word_en'],
                        'errors': serializer.errors
                    })
            except Exception as row_error:
                import_results['failed_entries'].append({
                    'row': index + 1,
                    'word_kh': row.get('word_kh', ''),
                    'word_en': row.get('word_en', ''),
                    'errors': str(row_error)
                })

        return import_results

    def _process_staging_word_relationships(self, staging_entry):
        """
        Process word relationships ONLY for ADMIN/SUPERUSER
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

    def _process_related_words(self, new_word, staging_entry):
        """
        Process related words ONLY for ADMIN/SUPERUSER
        """
        # Ensure mutually exclusive parent/child status
        if staging_entry.is_parent:
            new_word.is_parent = True
            new_word.is_child = False
        elif staging_entry.is_child:
            new_word.is_parent = False
            new_word.is_child = True

        new_word.save()

        # Find and link related words
        words = staging_entry.word_en.split()

        # Check for parent words
        for word in words:
            parent_word = Dictionary.objects.filter(word_en=word, is_parent=True).first()
            if parent_word:
                # Create RelatedWord entry
                RelatedWord.objects.get_or_create(
                    parent_word=parent_word,
                    child_word=new_word,
                    defaults={
                        'relationship_type': 'COMPOUND'
                    }
                )

    def _create_dictionary_entry(self, data, user, staging_entry=None):
        """
        Create Dictionary entry directly for ADMIN/SUPERUSER

        Args:
        - data: Dictionary of entry data
        - user: User creating the entry
        - staging_entry: Optional Staging entry for relationship processing
        """
        # Check for existing entry to prevent duplicates
        existing_entry = Dictionary.objects.filter(
            word_kh=data.get('word_kh', ''),
            word_en=data.get('word_en', '')
        ).first()

        if existing_entry:
            raise DRFValidationError({
                'non_field_errors': ['The fields word_kh, word_en must make a unique set.']
            })

        # Generate next index
        next_index = self._generate_unique_index()

        # Determine parent-child status
        is_parent = False
        is_child = False

        if staging_entry:
            is_parent = staging_entry.is_parent
            is_child = staging_entry.is_child
        else:
            # Fallback logic for parent-child detection if no staging entry
            words = data.get('word_en', '').split()
            is_parent = len(words) == 1 or not Dictionary.objects.filter(
                Q(word_en__in=words) & Q(is_parent=True)
            ).exists()
            is_child = not is_parent

        # Create Dictionary entry
        dictionary_entry = Dictionary.objects.create(
            index=next_index,
            word_kh=data.get('word_kh', ''),
            word_en=data.get('word_en', ''),
            word_kh_type=data.get('word_kh_type', ''),
            word_en_type=data.get('word_en_type', ''),
            word_kh_definition=data.get('word_kh_definition', ''),
            word_en_definition=data.get('word_en_definition', ''),
            pronunciation_kh=data.get('pronunciation_kh', ''),
            pronunciation_en=data.get('pronunciation_en', ''),
            example_sentence_kh=data.get('example_sentence_kh', ''),
            example_sentence_en=data.get('example_sentence_en', ''),
            created_by=user,
            is_parent=is_parent,
            is_child=is_child,
            is_deleted= 0
        )

        # Process related words if staging entry is provided and user is ADMIN/SUPERUSER
        if staging_entry and user.role in ['ADMIN', 'SUPERUSER']:
            self._process_related_words(dictionary_entry, staging_entry)

        return dictionary_entry

    def _generate_unique_index(self):
        """
        Generate a unique index for Dictionary entries
        """
        max_index = Dictionary.objects.aggregate(Max('index'))['index__max'] or 0
        return max_index + 1

    def validate_import_data(self, df):
        """
        Additional data validation before import
        """
        errors = []

        # Check required columns
        required_columns = ['word_kh', 'word_en', 'word_kh_type', 'word_en_type']
        for col in required_columns:
            if df[col].isnull().any():
                errors.append(f"Column {col} contains empty values")

        # Validate word types
        valid_kh_types = [type[0] for type in WordType.WORD_TYPE_CHOICES_KH]
        valid_en_types = [type[0] for type in WordType.WORD_TYPE_CHOICES_EN]

        invalid_kh_types = df[~df['word_kh_type'].isin(valid_kh_types)]
        invalid_en_types = df[~df['word_en_type'].isin(valid_en_types)]

        if not invalid_kh_types.empty:
            errors.append("Invalid Khmer word types found")

        if not invalid_en_types.empty:
            errors.append("Invalid English word types found")

        return errors

class ImportStatusView(APIView):
    permission_classes = [IsAuthenticated]

    @debug_error
    def get(self, request, task_id):
        try:
            # Retrieve import status from cache
            import_results = cache.get(f'import_task_{task_id}')

            if not import_results:
                return Response(
                    {'error': 'Task not found or expired'},
                    status=status.HTTP_404_NOT_FOUND
                )

            return Response(import_results)

        except Exception as e:
            logger.error(f"Import Status Error: {str(e)}")
            return Response(
                {
                    'error': 'An error occurred while fetching import status',
                    'details': str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

class DictionaryTemplateDownloadView(APIView):
    permission_classes = [IsAuthenticated]

    @debug_error
    def get(self, request):
        """
        Generate and provide downloadable Excel template with a unique filename
        """
        try:
            # Get a temporary directory
            import tempfile
            import os
            import io
            import uuid
            from datetime import datetime

            # Generate a unique filename with timestamp and/or UUID
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            unique_id = str(uuid.uuid4())[:8]  # Use first 8 characters of UUID

            # Create unique filename
            unique_filename = f"dictionary_import_template_{unique_id}.xlsx"

            # Create a temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                # Generate template in the temporary directory
                template_path = DictionaryTemplateGenerator.generate_template(
                    output_dir=temp_dir
                )
                # Validate template file exists
                if not os.path.exists(template_path):
                    raise FileNotFoundError(f"Template file not generated: {template_path}")
                # Open the file and read its content
                with open(template_path, 'rb') as template_file:
                    file_content = template_file.read()
                # Return file response with unique filename
                response = FileResponse(
                    io.BytesIO(file_content),
                    as_attachment=True,
                    filename=unique_filename
                )
                return response
        except Exception as e:
            # Log the full error details
            logger.error(f"Template Generation Error: {str(e)}", exc_info=True)
            return Response(
                {
                    'error': 'Failed to generate template',
                    'details': str(e)
                },
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class BookmarkView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve User Bookmarks",
        manual_parameters=[
            openapi.Parameter(
                'X-Device-ID',
                openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Unique Device Identifier',
                required=True
            )
        ],
        responses={
            200: openapi.Response(
                description='Bookmarks Retrieved Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'entries': openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(
                                        type=openapi.TYPE_OBJECT,
                                        properties={
                                            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                            'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                                            # 'word_kh_type': openapi.Schema(type=openapi.TYPE_STRING),
                                            # 'word_en_type': openapi.Schema(type=openapi.TYPE_STRING),
                                            # 'word_kh_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                            # 'word_en_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                            # 'created_at': openapi.Schema(type=openapi.TYPE_STRING, format='date-time')
                                        }
                                    )
                                ),
                                'total_entries': openapi.Schema(type=openapi.TYPE_INTEGER)
                            }
                        )
                    }
                )
            )
        }
    )
    @debug_error
    def get(self, request):
        try:
            # Get device ID from request headers
            device_id = request.headers.get('X-Device-ID')

            if not device_id:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Device ID is required',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            # Get bookmarks for the specific device
            bookmarks = Bookmark.objects.filter(device_id=device_id)

            # Prepare entries with dictionary details
            entries = []
            for bookmark in bookmarks:
                word = bookmark.word
                entries.append({
                    'id': word.id,
                    'word_kh': word.word_kh,
                    'word_en': word.word_en,
                    # 'word_kh_type': word.word_kh_type,
                    # 'word_en_type': word.word_en_type,
                    # 'word_kh_definition': word.word_kh_definition,
                    # 'word_en_definition': word.word_en_definition,
                    # 'created_at': bookmark.created_at.isoformat()
                })

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Bookmarks retrieved successfully',
                'data': {
                    'entries': entries,
                    'total_entries': len(entries)
                }
            })

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Failed to retrieve bookmarks',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Manage Bookmarks",
        tags=['mobile'],
        manual_parameters=[
            openapi.Parameter(
                'X-Device-ID',
                openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Unique Device Identifier',
                required=True
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['word_id', 'is_bookmark'],
            properties={
                'word_id': openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="ID of the word to bookmark/unbookmark"
                ),
                'is_bookmark': openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="Bookmark status (1 to add, 0 to remove)",
                    enum=[0, 1]
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='Bookmark Operation Successful',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'word_details': openapi.Schema(
                                    type=openapi.TYPE_OBJECT,
                                    properties={
                                        'word_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                        'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                        'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                                        'is_bookmark': openapi.Schema(type=openapi.TYPE_INTEGER)
                                    }
                                )
                            }
                        )
                    }
                )
            ),
            400: 'Bad Request - Missing Device ID or Word ID',
            404: 'Word Not Found',
            500: 'Internal Server Error'
        }
    )
    def post(self, request):
        try:
            # Get device ID from request headers
            device_id = request.headers.get('X-Device-ID')

            if not device_id:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Device ID is required',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            # Get word_id and is_bookmark from request data
            word_id = request.data.get('word_id')
            is_bookmark = request.data.get('is_bookmark')

            # Validate input parameters
            if word_id is None or is_bookmark is None:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Word ID and is_bookmark are required',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            # Validate word_id exists
            try:
                word = Dictionary.objects.get(id=word_id)
            except Dictionary.DoesNotExist:
                return Response({
                    'responseCode': status.HTTP_404_NOT_FOUND,
                    'message': 'Word not found',
                    'data': []
                }, status=status.HTTP_404_NOT_FOUND)

            # Handle bookmark logic
            if is_bookmark == 1:
                # Create bookmark if it doesn't exist
                bookmark, created = Bookmark.objects.get_or_create(
                    device_id=device_id,
                    word=word
                )
                message = 'Bookmark added successfully'
            elif is_bookmark == 0:
                # Remove bookmark if it exists
                try:
                    bookmark = Bookmark.objects.get(
                        device_id=device_id,
                        word=word
                    )
                    bookmark.delete()
                    message = 'Bookmark removed successfully'
                except Bookmark.DoesNotExist:
                    # If trying to remove a non-existent bookmark, return success
                    message = 'Bookmark not found'

            # Prepare response data
            response_data = {
                'word_details': {
                    'word_id': word.id,
                    'word_kh': word.word_kh,
                    'word_en': word.word_en,
                    'is_bookmark': is_bookmark
                }
            }

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': message,
                'data': response_data
            })

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Failed to process bookmark',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Delete a Bookmark",
        tags=['mobile'],
        manual_parameters=[
            openapi.Parameter(
                'X-Device-ID',
                openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Unique Device Identifier',
                required=True
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['word_id'],
            properties={
                'word_id': openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="ID of the word to remove from bookmarks"
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='Bookmark Deleted Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'word_details': openapi.Schema(
                                    type=openapi.TYPE_OBJECT,
                                    properties={
                                        'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                        'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                                        'definition_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                        'definition_en': openapi.Schema(type=openapi.TYPE_STRING)
                                    }
                                )
                            }
                        )
                    }
                )
            ),
            400: 'Bad Request - Missing Device ID or Word ID',
            404: 'Bookmark Not Found',
            500: 'Internal Server Error'
        }
    )
    def delete(self, request):
        try:
            # Get device ID from request headers
            device_id = request.headers.get('X-Device-ID')

            if not device_id:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Device ID is required',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            # Get word_id from request data
            word_id = request.data.get('word_id')

            if not word_id:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Word ID is required',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            # Find and delete the bookmark
            bookmark = Bookmark.objects.filter(
                device_id=device_id,
                word_id=word_id
            ).first()

            if not bookmark:
                return Response({
                    'responseCode': status.HTTP_404_NOT_FOUND,
                    'message': 'Bookmark not found',
                    'data': []
                }, status=status.HTTP_404_NOT_FOUND)

            # Use existing BookmarkSerializer to get word details before deletion
            serializer = BookmarkSerializer(bookmark)
            bookmark_data = serializer.data

            # Delete the bookmark
            bookmark.delete()

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Bookmark deleted successfully',
                'data': bookmark_data
            })

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Failed to delete bookmark',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DictionarySyncAllView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Full Dictionary Synchronization for Mobile App",
        tags=['mobile'],
        manual_parameters=[
            openapi.Parameter(
                'X-Device-ID',
                openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Unique Device Identifier',
                required=True
            ),
            openapi.Parameter(
                'page',
                openapi.IN_QUERY,
                description="Page number for pagination",
                type=openapi.TYPE_INTEGER,
                default=1
            ),
            openapi.Parameter(
                'per_page',
                openapi.IN_QUERY,
                description="Number of entries per page",
                type=openapi.TYPE_INTEGER,
                default=25
            )
        ],
        responses={
            200: openapi.Response(
                description='Full Dictionary Sync Successful',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'entries': openapi.Schema(
                                    type=openapi.TYPE_ARRAY,
                                    items=openapi.Schema(type=openapi.TYPE_OBJECT)
                                ),
                                'total_entries': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'page': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'per_page': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'total_pages': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'last_sync_timestamp': openapi.Schema(type=openapi.TYPE_STRING),
                                'current_sync_timestamp': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            )
        }
    )
    @debug_error
    def get(self, request):
        try:
            # Get device ID from headers
            device_id = request.headers.get('X-Device-ID')
            page = max(1, int(request.GET.get('page', 1)))
            per_page = max(1, int(request.GET.get('per_page', 50)))

            # Validate device ID
            if not device_id:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Device ID is required',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Get all bookmarked word IDs for this device in one query
            bookmarked_ids = set(Bookmark.objects.filter(device_id=device_id)
                                .values_list('word_id', flat=True))

            # Calculate pagination
            # Prioritize parent words, then other entries
            # Exclude deleted entries
            entries_query = Dictionary.objects.filter(is_deleted=False).annotate(
                parent_priority=Case(
                    When(is_parent=True, then=Value(0)),
                    default=Value(1),
                    output_field=IntegerField()
                )
            ).order_by('parent_priority', 'id')

            # Prefetch related words for parent entries
            entries_query = entries_query.prefetch_related(
                Prefetch(
                    'child_words',
                    queryset=RelatedWord.objects.select_related('child_word'),
                    to_attr='prefetched_child_words'
                )
            )

            # Calculate total entries and pages
            total_entries = entries_query.count()
            total_pages = (total_entries + per_page - 1) // per_page

            # Apply pagination
            entries = entries_query[(page-1)*per_page : page*per_page]

            # Serialize entries with related words and bookmark status
            serializer = DictionaryEntrySerializer(
                entries,
                many=True,
                context={'request': request, 'bookmarked_ids': bookmarked_ids}
            )

            # Prepare response
            current_time = timezone.now()
            response_data = {
                'entries': serializer.data,
                'total_entries': total_entries,
                'page': page,
                'per_page': per_page,
                'total_pages': total_pages,
                'last_sync_timestamp': (current_time - timezone.timedelta(minutes=2)).isoformat(),
                'current_sync_timestamp': current_time.isoformat()
            }

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Full dictionary synced successfully',
                'data': response_data
            })

        except Exception as e:
            # Detailed error logging
            logger.error(f"Sync error: {str(e)}", exc_info=True)

            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Internal server error',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DictionarySyncView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Incremental Dictionary Synchronization",
        tags=['mobile'],
        manual_parameters=[
            openapi.Parameter(
                'X-Device-ID',
                openapi.IN_HEADER,
                type=openapi.TYPE_STRING,
                description='Unique Device Identifier',
                required=True
            ),
            openapi.Parameter(
                'last_sync_timestamp',
                openapi.IN_QUERY,
                type=openapi.TYPE_STRING,
                description='Timestamp of last synchronization (ISO format)',
                required=True
            )
        ],
        responses={
            200: openapi.Response(
                description='Incremental Sync Successful',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'responseCode': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'data': openapi.Schema(type=openapi.TYPE_OBJECT)
                    }
                )
            )
        }
    )
    @debug_error
    def get(self, request):
        try:
            # Get device ID and last sync timestamp
            device_id = request.headers.get('X-Device-ID')
            last_sync_timestamp = request.query_params.get('last_sync_timestamp')

            # Validate required parameters
            if not device_id:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Device ID is required',
                    'data': {}
                }, status=status.HTTP_400_BAD_REQUEST)

            if not last_sync_timestamp:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Last sync timestamp is required',
                    'data': {}
                }, status=status.HTTP_400_BAD_REQUEST)

            try:
                last_sync_time = timezone.datetime.fromisoformat(last_sync_timestamp)
            except ValueError:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid timestamp format. Use ISO format (YYYY-MM-DDTHH:MM:SS.mmmmmm+HH:MM)',
                    'data': {}
                }, status=status.HTTP_400_BAD_REQUEST)

            # Get all bookmarked word IDs for this device in one query
            bookmarked_ids = set(Bookmark.objects.filter(device_id=device_id)
                                .values_list('word_id', flat=True))

            # Get updated entries since last sync
            updated_entries = Dictionary.objects.filter(
                Q(created_at__gt=last_sync_time) |
                Q(updated_at__gt=last_sync_time) |
                Q(is_deleted=True, deleted_at__gt=last_sync_time)

            ).prefetch_related(
                Prefetch(
                    'child_words',
                    queryset=RelatedWord.objects.select_related('child_word'),
                    to_attr='prefetched_child_words'
                )
            )

            # Current timestamp for this sync
            current_sync_timestamp = timezone.now().isoformat()

            # Serialize updated entries
            serializer = DictionaryEntrySerializer(
                updated_entries,
                many=True,
                context={'request': request, 'bookmarked_ids': bookmarked_ids}
            )

            # Prepare response data
            sync_data = {
                'entries': serializer.data,
                'total_entries': updated_entries.count(),
                'page': 1,
                'per_page': updated_entries.count(),
                'total_pages': 1,
                'last_sync_timestamp': last_sync_timestamp,
                'current_sync_timestamp': current_sync_timestamp
            }

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Dictionary entries retrieved successfully',
                'data': sync_data
            })

        except Exception as e:
            logger.error(f"Sync error: {str(e)}", exc_info=True)
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'An error occurred during dictionary sync',
                'data': {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
