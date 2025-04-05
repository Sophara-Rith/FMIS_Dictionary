# dictionary/views.py
import time
import logging
from functools import wraps, reduce
import operator
import hashlib
import pandas as pd
import os
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.utils import timezone
from django.http import FileResponse
from django.core.cache import cache
from django.conf import settings
from django.db.models import Q, Max, Case, When, Value, IntegerField
from .models import Dictionary, Staging, Bookmark, WordType, RelatedWord
from .serializers import (
    DictionaryEntrySerializer,
    BookmarkSerializer,
    StagingEntrySerializer,
    StagingEntryCreateSerializer,
)
from debug_utils import debug_error
from .tasks import process_staging_bulk_import
from .utils import DictionaryTemplateGenerator
from dictionary import models

logger = logging.getLogger(__name__)

class DictionaryEntryListView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all approved dictionary entries",
        manual_parameters=[
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
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'word': openapi.Schema(type=openapi.TYPE_STRING),
                            'definition': openapi.Schema(type=openapi.TYPE_STRING),
                            'language': openapi.Schema(type=openapi.TYPE_STRING),
                        }
                    )
                )
            )
        }
    )
    @debug_error
    def get(self, request):
        # Get query parameters
        language = request.query_params.get('language')
        search = request.query_params.get('search')

        # Base queryset
        entries = Dictionary.objects.all()

        # Apply filters
        if language:
            entries = entries.filter(language=language)

        if search:
            entries = entries.filter(word__icontains=search)

        # Serialize and return
        serializer = DictionaryEntrySerializer(entries, many=True)
        return Response(serializer.data)

class DictionaryEntryDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve a specific dictionary entry by ID",
        responses={
            200: openapi.Response(
                description='Successful retrieval of dictionary entry',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'word': openapi.Schema(type=openapi.TYPE_STRING),
                        'definition': openapi.Schema(type=openapi.TYPE_STRING),
                        'language': openapi.Schema(type=openapi.TYPE_STRING),
                        'examples': openapi.Schema(type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_STRING)),
                    }
                )
            ),
            404: 'Entry Not Found'
        }
    )
    @debug_error
    def get(self, request, pk):
        try:
            entry = Dictionary.objects.get(pk=pk)
            serializer = DictionaryEntrySerializer(entry)
            return Response(serializer.data)
        except Dictionary.DoesNotExist:
            return Response(
                {'error': 'Dictionary entry not found'},
                status=status.HTTP_404_NOT_FOUND
            )

class StagingEntryListView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="List all staging entries pending approval",
        responses={
            200: openapi.Response(
                description='Successful retrieval of staging entries',
                schema=openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(
                        type=openapi.TYPE_OBJECT,
                        properties={
                            'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                            'word': openapi.Schema(type=openapi.TYPE_STRING),
                            'definition': openapi.Schema(type=openapi.TYPE_STRING),
                            'submitted_by': openapi.Schema(type=openapi.TYPE_STRING),
                            'created_at': openapi.Schema(type=openapi.TYPE_STRING, format='date-time'),
                        }
                    )
                )
            )
        }
    )
    @debug_error
    def get(self, request):
        entries = Staging.objects.all()
        serializer = StagingEntrySerializer(entries, many=True)
        return Response(serializer.data)

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
                description='Staging entry created successfully',
                schema=openapi.Schema(
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
                )
            ),
            400: 'Validation Error'
        }
    )
    @debug_error
    def post(self, request):
        serializer = StagingEntryCreateSerializer(
            data=request.data,
            context={'request': request}
        )

        if serializer.is_valid():
            # Save staging entry
            staging_entry = serializer.save()

            # Process related words
            self._process_related_words(staging_entry)

            return Response({
                'responseCode': status.HTTP_201_CREATED,
                'message': 'Staging entry created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)

        return Response({
            'responseCode': status.HTTP_400_BAD_REQUEST,
            'message': 'Invalid data',
            'errors': serializer.errors
        }, status=status.HTTP_400_BAD_REQUEST)

    def _process_related_words(self, staging_entry):
        # Process Khmer words
        kh_words = staging_entry.word_kh.split()
        self._find_and_link_related_words(kh_words, staging_entry, 'word_kh')

        # Process English words
        en_words = staging_entry.word_en.split()
        self._find_and_link_related_words(en_words, staging_entry, 'word_en')

    def _find_and_link_related_words(self, words, staging_entry, word_field):
        # Single word scenario
        if len(words) == 1:
            # Check if word already exists in dictionary
            existing_word = Dictionary.objects.filter(**{word_field: words[0]}).first()
            if not existing_word:
                # If single word and not in dictionary, mark as potential parent
                staging_entry.is_parent = True
                staging_entry.is_child = False
                staging_entry.save()
            return

        # Multiple word scenario
        parent_words = []
        full_phrase = ' '.join(words)

        # Check each word if it exists in dictionary
        for word in words:
            existing_word = Dictionary.objects.filter(**{word_field: word}).first()
            if existing_word and existing_word.is_parent:
                # If word exists and is a parent, add to potential parents
                parent_words.append(existing_word)

        # If we have parent words, mark the full phrase as a child
        if parent_words:
            staging_entry.is_parent = False
            staging_entry.is_child = True
            staging_entry.save()

            # Create related word entries for each parent word
            for parent_word in parent_words:
                RelatedWord.objects.get_or_create(
                    parent_word=parent_word,
                    child_word=Dictionary.objects.filter(**{word_field: full_phrase}).first(),
                    defaults={
                        'relationship_type': 'COMPOUND'
                    }
                )

    def _generate_unique_index(self):
        # Generate a unique index
        max_index = Dictionary.objects.aggregate(Max('index'))['index__max'] or 0
        return max_index + 1

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

class StagingEntryApproveView(APIView):
    def post(self, request, pk):
        try:
            # Retrieve the staging entry
            staging_entry = Staging.objects.get(id=pk)

            # Generate next index
            next_index = self._generate_unique_index()

            # Create Dictionary entry
            dictionary_entry = Dictionary.objects.create(
                index=next_index,
                word_kh=staging_entry.word_kh,
                word_en=staging_entry.word_en,
                word_kh_type=staging_entry.word_kh_type,
                word_en_type=staging_entry.word_en_type,
                word_kh_definition=staging_entry.word_kh_definition,
                word_en_definition=staging_entry.word_en_definition,
                created_by=request.user,

                # Transfer parent-child status from staging
                is_parent=staging_entry.is_parent,
                is_child=staging_entry.is_child
            )

            # Process related words if it's a multi-word entry
            if staging_entry.is_child:
                self._process_related_words(dictionary_entry, staging_entry)

            # Update staging entry status
            staging_entry.review_status = 'APPROVED'
            staging_entry.save()

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Staging entry approved successfully',
                'data': {
                    'id': dictionary_entry.id,
                    'is_parent': dictionary_entry.is_parent,
                    'is_child': dictionary_entry.is_child
                }
            })

        except Staging.DoesNotExist:
            return Response({
                'responseCode': status.HTTP_404_NOT_FOUND,
                'message': 'Staging entry not found'
            }, status=status.HTTP_404_NOT_FOUND)

    def _process_related_words(self, new_word, staging_entry):
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
        full_phrase = staging_entry.word_en

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

    def _generate_unique_index(self):
        max_index = Dictionary.objects.aggregate(Max('index'))['index__max'] or 0
        return max_index + 1

class StagingEntryRejectView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="Reject a staging entry",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'reason': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Reason for rejection"
                )
            }
        ),
        responses={
            200: 'Staging entry rejected successfully',
            404: 'Staging Entry Not Found'
        }
    )
    @debug_error
    def post(self, request, pk):
        try:
            staging_entry = Staging.objects.get(pk=pk)

            # Optional: Log rejection reason
            reason = request.data.get('reason', 'No reason provided')

            # Delete staging entry
            staging_entry.delete()

            return Response({
                'message': 'Entry rejected and deleted',
                'reason': reason
            }, status=status.HTTP_200_OK)
        except Staging.DoesNotExist:
            return Response(
                {'error': 'Staging entry not found'},
                status=status.HTTP_404_NOT_FOUND
            )

class StagingEntryDetailView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Retrieve details of a specific staging entry",
        responses={
            200: openapi.Response(
                description='Successful retrieval of staging entry details',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                        'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                        'word_kh_type': openapi.Schema(type=openapi.TYPE_STRING),
                        'word_en_type': openapi.Schema(type=openapi.TYPE_STRING),
                        'word_kh_definition': openapi.Schema(type=openapi.TYPE_STRING),
                        'word_en_definition': openapi.Schema(type=openapi.TYPE_STRING),
                        'review_status': openapi.Schema(type=openapi.TYPE_STRING),
                        'created_at': openapi.Schema(type=openapi.TYPE_STRING, format='date-time'),
                        'created_by': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            404: 'Staging Entry Not Found'
        }
    )
    @debug_error
    def get(self, request, pk):
        try:
            staging_entry = Staging.objects.get(pk=pk)

            # Check if user is admin or the creator of the entry
            if not (request.user.is_staff or
                    staging_entry.created_by == request.user):
                return Response(
                    {'error': 'You are not authorized to view this entry'},
                    status=status.HTTP_403_FORBIDDEN
                )

            serializer = StagingEntrySerializer(staging_entry)
            return Response(serializer.data)
        except Staging.DoesNotExist:
            return Response(
                {'error': 'Staging entry not found'},
                status=status.HTTP_404_NOT_FOUND
            )

class StagingEntryUpdateView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Update a staging entry",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                'word_kh_type': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    enum=[choice[0] for choice in WordType.WORD_TYPE_CHOICES_KH]
                ),
                'word_en_type': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    enum=[choice[0] for choice in WordType.WORD_TYPE_CHOICES_EN]
                ),
                'word_kh_definition': openapi.Schema(type=openapi.TYPE_STRING),
                'word_en_definition': openapi.Schema(type=openapi.TYPE_STRING),
                'pronunciation_kh': openapi.Schema(type=openapi.TYPE_STRING),
                'pronunciation_en': openapi.Schema(type=openapi.TYPE_STRING),
                'example_sentence_kh': openapi.Schema(type=openapi.TYPE_STRING),
                'example_sentence_en': openapi.Schema(type=openapi.TYPE_STRING)
            }
        ),
        responses={
            200: 'Staging entry updated successfully',
            400: 'Validation error',
            403: 'Unauthorized',
            404: 'Staging entry not found'
        }
    )
    @debug_error
    def put(self, request, pk):
        try:
            staging_entry = Staging.objects.get(pk=pk)

            # Only allow updates by the creator or admin
            if not (request.user.is_staff or
                    staging_entry.created_by == request.user):
                return Response(
                    {'error': 'You are not authorized to update this entry'},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Prevent updates to approved or rejected entries
            if staging_entry.review_status != 'PENDING':
                return Response(
                    {'error': 'Cannot update non-pending entries'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            serializer = StagingEntryCreateSerializer(
                staging_entry,
                data=request.data,
                partial=True,
                context={'request': request}
            )

            if serializer.is_valid():
                serializer.save()
                return Response(serializer.data)

            return Response(
                serializer.errors,
                status=status.HTTP_400_BAD_REQUEST
            )
        except Staging.DoesNotExist:
            return Response(
                {'error': 'Staging entry not found'},
                status=status.HTTP_404_NOT_FOUND
            )

class StagingEntryDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Delete a staging entry",
        responses={
            204: 'Staging entry deleted successfully',
            403: 'Unauthorized to delete',
            404: 'Staging entry not found'
        }
    )
    @debug_error
    def delete(self, request, pk):
        try:
            staging_entry = Staging.objects.get(pk=pk)

            # Only allow deletion by the creator or admin
            if not (request.user.is_staff or
                    staging_entry.created_by == request.user):
                return Response(
                    {'error': 'You are not authorized to delete this entry'},
                    status=status.HTTP_403_FORBIDDEN
                )

            # Prevent deletion of non-pending entries
            if staging_entry.review_status != 'PENDING':
                return Response(
                    {'error': 'Cannot delete non-pending entries'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            staging_entry.delete()
            return Response(
                {'message': 'Staging entry deleted successfully'},
                status=status.HTTP_204_NO_CONTENT
            )
        except Staging.DoesNotExist:
            return Response(
                {'error': 'Staging entry not found'},
                status=status.HTTP_404_NOT_FOUND
            )

class BookmarkRateThrottle(UserRateThrottle):
    """
    Custom rate throttle to handle multiple device access
    """
    def get_cache_key(self, request, view):
        # Use device ID instead of user ID for rate limiting
        device_id = request.headers.get('X-Device-ID')
        return f'throttle_device_{device_id}'

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
                default=10
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
            per_page = max(1, int(request.query_params.get('per_page', 10)))

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
                        'total_entries': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'successful_entries': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'failed_entries': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'row': openapi.Schema(type=openapi.TYPE_INTEGER),
                                    'errors': openapi.Schema(type=openapi.TYPE_OBJECT)
                                }
                            )
                        )
                    }
                )
            ),
            400: 'Invalid File or Data'
        }
    )
    @debug_error
    def post(self, request):
        # Validate file upload
        if 'file' not in request.FILES:
            return Response(
                {'error': 'No file uploaded'},
                status=status.HTTP_400_BAD_REQUEST
            )

        excel_file = request.FILES['file']

        # Validate file type
        if not excel_file.name.endswith(('.xlsx', '.xls')):
            return Response(
                {'error': 'Invalid file type. Please upload an Excel file.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            # Read Excel file
            df = pd.read_excel(excel_file)

            # Attempt to rename columns using the mapping
            try:
                # If Khmer headers are used
                if any(col in self.COLUMN_NAME_MAPPING for col in df.columns):
                    df.rename(columns=self.COLUMN_NAME_MAPPING, inplace=True)

                # Validate column names
                if list(df.columns) != self.EXPECTED_COLUMNS:
                    return Response({
                        'error': 'Column names do not match the template. Do not modify headers!',
                        'expected_columns': self.EXPECTED_COLUMNS,
                        'actual_columns': list(df.columns)
                    }, status=status.HTTP_400_BAD_REQUEST)

            except Exception as column_error:
                return Response({
                    'error': f'Column mapping error: {str(column_error)}',
                    'expected_columns': self.EXPECTED_COLUMNS,
                    'actual_columns': list(df.columns)
                }, status=status.HTTP_400_BAD_REQUEST)

            # Prepare results tracking
            successful_entries = []
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

                    if serializer.is_valid():
                        # Save the staging entry
                        staging_entry = serializer.save()
                        successful_entries.append({
                            'row': index + 2,  # Excel rows start at 1, add header
                            'word_kh': staging_entry.word_kh,
                            'word_en': staging_entry.word_en
                        })
                    else:
                        # Collect validation errors
                        failed_entries.append({
                            'row': index + 2,
                            'errors': serializer.errors
                        })

                except Exception as entry_error:
                    # Catch any unexpected errors during entry processing
                    failed_entries.append({
                        'row': index + 2,
                        'errors': str(entry_error)
                    })

            # Prepare and return response
            return Response({
                'total_entries': len(df),
                'successful_entries': len(successful_entries),
                'successful_details': successful_entries,
                'failed_entries': failed_entries
            }, status=status.HTTP_200_OK if len(failed_entries) < len(df) else status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Log the full error for debugging
            logger.error(f"Bulk import error: {str(e)}", exc_info=True)

            return Response({
                'error': 'An error occurred during file processing',
                'details': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

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

    def get(self, request):
        """
        Generate and provide downloadable Excel template
        """
        try:
            # Ensure MEDIA_ROOT is configured
            if not hasattr(settings, 'MEDIA_ROOT'):
                raise ValueError("MEDIA_ROOT is not configured in settings")

            # Create media directory if it doesn't exist
            media_dir = settings.MEDIA_ROOT
            os.makedirs(media_dir, exist_ok=True)

            # Create import templates subdirectory
            templates_dir = os.path.join(media_dir, 'import_templates')
            os.makedirs(templates_dir, exist_ok=True)

            # Generate template with explicit directory
            template_path = DictionaryTemplateGenerator.generate_template(
                output_dir=templates_dir
            )

            # Validate template file exists
            if not os.path.exists(template_path):
                raise FileNotFoundError(f"Template file not generated: {template_path}")

            # Open file for reading
            try:
                template_file = open(template_path, 'rb')
            except IOError as io_err:
                logger.error(f"Failed to open template file: {io_err}")
                return Response(
                    {
                        'error': 'Failed to access template file',
                        'details': str(io_err)
                    },
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR
                )

            # Return file response
            response = FileResponse(
                template_file,
                as_attachment=True,
                filename='dictionary_import_template.xlsx'
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
                type=openapi.TYPE_INTEGER,
                description='Page number for pagination',
                default=1
            ),
            openapi.Parameter(
                'per_page',
                openapi.IN_QUERY,
                type=openapi.TYPE_INTEGER,
                description='Number of items per page',
                default=25
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
                                            'word_kh_type': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_en_type': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_kh_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_en_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                            'created_at': openapi.Schema(type=openapi.TYPE_STRING, format='date-time')
                                        }
                                    )
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

            # Safely get pagination parameters
            page = max(1, int(request.GET.get('page', 1)))
            per_page = max(1, int(request.GET.get('per_page', 25)))

            # Get bookmarks for the specific device
            bookmarks = Bookmark.objects.filter(device_id=device_id)

            # Calculate pagination
            total_entries = bookmarks.count()
            total_pages = (total_entries + per_page - 1) // per_page

            # Apply pagination
            start = (page - 1) * per_page
            end = start + per_page
            paginated_bookmarks = bookmarks[start:end]

            # Prepare entries with dictionary details
            entries = []
            for bookmark in paginated_bookmarks:
                word = bookmark.word
                entries.append({
                    'id': word.id,
                    'word_kh': word.word_kh,
                    'word_en': word.word_en,
                    'word_kh_type': word.word_kh_type,
                    'word_en_type': word.word_en_type,
                    'word_kh_definition': word.word_kh_definition,
                    'word_en_definition': word.word_en_definition,
                    'created_at': word.created_at.isoformat()
                })

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Bookmarks retrieved successfully',
                'data': {
                    'entries': entries,
                    'total_entries': total_entries,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': total_pages
                }
            })

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Failed to retrieve bookmarks',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Create a Bookmark",
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
                    description="ID of the word to bookmark"
                )
            }
        ),
        responses={
            201: openapi.Response(
                description='Bookmark Created Successfully',
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

            # Get word_id from request data
            word_id = request.data.get('word_id')

            if not word_id:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Word ID is required',
                    'data': []
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if word exists
            try:
                word = Dictionary.objects.get(id=word_id)
            except Dictionary.DoesNotExist:
                return Response({
                    'responseCode': status.HTTP_404_NOT_FOUND,
                    'message': 'Word not found',
                    'data': []
                }, status=status.HTTP_404_NOT_FOUND)

            # Create or get bookmark
            bookmark, created = Bookmark.objects.get_or_create(
                device_id=device_id,
                word=word
            )

            # Use existing BookmarkSerializer to get word details
            serializer = BookmarkSerializer(bookmark)

            return Response({
                'responseCode': status.HTTP_201_CREATED if created else status.HTTP_200_OK,
                'message': 'Bookmark added successfully' if created else 'Bookmark already exists',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

        except Exception as e:
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Failed to add bookmark',
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

class DictionarySyncView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Sync dictionary entries since last synchronization",
        tags=['mobile'],
        manual_parameters=[
            openapi.Parameter(
                'last_sync_timestamp',
                openapi.IN_QUERY,
                description="Timestamp of last synchronization to fetch updated entries",
                type=openapi.TYPE_STRING,
                required=True
            )
        ],
        responses={
            200: openapi.Response(
                description='Dictionary Sync Successful',
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
                                            'word_kh_type': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_en_type': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_kh_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_en_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                            'sync_status': openapi.Schema(type=openapi.TYPE_STRING)
                                        }
                                    )
                                ),
                                'total_entries': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'last_sync_timestamp': openapi.Schema(type=openapi.TYPE_STRING),
                                'current_sync_timestamp': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            )
        }
    )
    def get(self, request):
        try:
            # Extract last sync timestamp (required parameter)
            last_sync_timestamp = request.query_params.get('last_sync_timestamp')

            # Validate timestamp format
            try:
                last_sync = timezone.datetime.fromisoformat(last_sync_timestamp)
            except (ValueError, TypeError):
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Invalid last_sync_timestamp format. Use ISO format.',
                    'data': {}
                }, status=status.HTTP_400_BAD_REQUEST)

            # Query for new and updated entries since last sync
            updated_entries = Dictionary.objects.filter(
                Q(created_at__gt=last_sync) |  # New entries
                Q(updated_at__gt=last_sync)    # Updated existing entries
            )

            # Prepare current sync timestamp
            current_sync_timestamp = timezone.now().isoformat()

            # Prepare sync data
            sync_data = {
                'entries': [{
                    'id': entry.id,
                    'word_kh': entry.word_kh,
                    'word_en': entry.word_en,
                    'word_kh_type': entry.word_kh_type,
                    'word_en_type': entry.word_en_type,
                    'word_kh_definition': entry.word_kh_definition,
                    'word_en_definition': entry.word_en_definition,
                    'sync_status': self._get_sync_status(entry, last_sync)
                } for entry in updated_entries],
                'total_entries': updated_entries.count(),
                'last_sync_timestamp': last_sync_timestamp,
                'current_sync_timestamp': current_sync_timestamp
            }

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Dictionary entries retrieved successfully',
                'data': sync_data
            })

        except Exception as e:
            logger.error(f"Sync error: {str(e)}")
            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'An error occurred during dictionary sync',
                'data': {}
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def _get_sync_status(self, entry, last_sync):
        """
        Determine sync status of an entry
        """
        if entry.created_at > last_sync:
            return 'NEW'
        elif entry.updated_at > last_sync:
            return 'UPDATED'
        return 'UNCHANGED'

class DictionarySyncAllView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Full Dictionary Synchronization",
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
                                            'is_bookmark': openapi.Schema(type=openapi.TYPE_INTEGER)
                                        }
                                    )
                                )
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

            # Validate device ID
            if not device_id:
                return Response({
                    'responseCode': status.HTTP_400_BAD_REQUEST,
                    'message': 'Device ID is required',
                    'data': None
                }, status=status.HTTP_400_BAD_REQUEST)

            # Pagination parameters
            page = max(1, int(request.GET.get('page', 1)))
            per_page = max(1, int(request.GET.get('per_page', 20)))

            # Calculate pagination
            # Prioritize parent words, then other entries
            entries = Dictionary.objects.annotate(
                parent_priority=Case(
                    When(is_parent=True, then=Value(0)),
                    default=Value(1),
                    output_field=IntegerField()
                )
            ).order_by('parent_priority', 'id')[
                (page-1)*per_page : page*per_page
            ]

            # Calculate total entries and pages
            total_entries = Dictionary.objects.count()
            total_pages = (total_entries + per_page - 1) // per_page

            # Serialize entries with related words and bookmark status
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
                'total_pages': total_pages,
                'last_sync_timestamp': (timezone.now() - timezone.timedelta(minutes=2)).isoformat(),
                'current_sync_timestamp': timezone.now().isoformat()
            }

            return Response({
                'responseCode': status.HTTP_200_OK,
                'message': 'Full dictionary synced successfully',
                'data': response_data
            })

        except Exception as e:
            # Detailed error logging
            import traceback
            print(traceback.format_exc())

            return Response({
                'responseCode': status.HTTP_500_INTERNAL_SERVER_ERROR,
                'message': 'Internal server error',
                'data': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
