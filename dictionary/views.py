# dictionary/views.py
import time
import logging
from functools import wraps, reduce
import operator
import traceback
import uuid
import hashlib
import pandas as pd
import os
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser, AllowAny
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle, AnonRateThrottle
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from django.utils import timezone
from django.http import FileResponse
from django.core.cache import cache
from django.conf import settings
from django.db.models import Q
from .models import Dictionary, Staging, Bookmark, WordType
from .serializers import (
    DictionaryEntrySerializer,
    BookmarkSerializer,
    StagingEntrySerializer,
    StagingEntryCreateSerializer,
    DictionaryEntrySyncSerializer
)
from debug_utils import debug_error
from .tasks import process_staging_bulk_import
from .utils import DictionaryTemplateGenerator

logger = logging.getLogger(__name__)

class DictionaryEntryListView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List all approved dictionary entries",
        manual_parameters=[
            openapi.Parameter(
                'language',
                openapi.IN_QUERY,
                description="Filter entries by language (KH-EN or EN-KH)",
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
            serializer.save()
            return Response({
                'message': 'Data successfully insert.'
            },status=status.HTTP_201_CREATED
            )
        return Response(
            serializer.errors,
            status=status.HTTP_400_BAD_REQUEST
        )

class StagingEntryApproveView(APIView):
    permission_classes = [IsAdminUser]

    @swagger_auto_schema(
        operation_description="Approve a staging entry and add to dictionary",
        responses={
            200: openapi.Response(
                description='Staging entry approved and added to dictionary',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'entry': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'word': openapi.Schema(type=openapi.TYPE_STRING),
                                'definition': openapi.Schema(type=openapi.TYPE_STRING),
                            }
                        )
                    }
                )
            ),
            404: 'Staging Entry Not Found'
        }
    )
    @debug_error
    def post(self, request, pk):
        try:
            # Retrieve the staging entry
            staging_entry = Staging.objects.get(pk=pk)

            # Create dictionary entry with all relevant fields
            dictionary_entry = Dictionary.objects.create(
                index=staging_entry.id,

                # Core word fields
                word_kh=staging_entry.word_kh,
                word_en=staging_entry.word_en,

                # Word type fields
                word_kh_type=staging_entry.word_kh_type,
                word_en_type=staging_entry.word_en_type,

                # Definition fields
                word_kh_definition=staging_entry.word_kh_definition,
                word_en_definition=staging_entry.word_en_definition,

                # Optional fields
                pronunciation_kh=staging_entry.pronunciation_kh,
                pronunciation_en=staging_entry.pronunciation_en,
                example_sentence_kh=staging_entry.example_sentence_kh,
                example_sentence_en=staging_entry.example_sentence_en,

                # Metadata
                created_by=request.user,  # The admin who approves the entry
                created_at=timezone.now()
            )

            # Update staging entry status
            staging_entry.review_status = 'APPROVED'
            staging_entry.reviewed_by = request.user
            staging_entry.reviewed_at = timezone.now()
            staging_entry.save()

            # Delete the staging entry after approval
            staging_entry.delete()

            return Response({
                'message': 'Entry approved and added to dictionary',
                'entry': {
                    'id': dictionary_entry.index,
                    'word_kh': dictionary_entry.word_kh,
                    'word_en': dictionary_entry.word_en
                }
            }, status=status.HTTP_200_OK)

        except Staging.DoesNotExist:
            return Response(
                {'error': 'Staging entry not found'},
                status=status.HTTP_404_NOT_FOUND
            )
        except Exception as e:
            # Log the error for debugging
            logger.error(f"Error approving staging entry: {str(e)}")
            return Response(
                {'error': 'An error occurred while approving the entry'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

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

class BookmarkView(APIView):
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]
    throttle_classes = [BookmarkRateThrottle]

    def validate_device_id(self, request):
        """
        Validate device ID from request
        """
        device_id = request.headers.get('X-Device-ID')
        if not device_id:
            raise ValueError("Device ID is required in X-Device-ID header")
        return device_id

    @swagger_auto_schema(
        operation_description="Add a bookmark for a word",
        tags=['mobile'],
        manual_parameters=[
            openapi.Parameter(
                'X-Device-ID',
                openapi.IN_HEADER,
                description="Unique Device Identifier",
                type=openapi.TYPE_STRING,
                required=True
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['word_id'],
            properties={
                'word_id': openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="ID of the dictionary entry to bookmark"
                )
            }
        ),
        responses={
            201: openapi.Response(
                description='Bookmark Added Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Success message'
                        ),
                        'bookmark': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'word_details': openapi.Schema(
                                    type=openapi.TYPE_OBJECT,
                                    properties={
                                        'word_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                        'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                        'word_kh_type': openapi.Schema(type=openapi.TYPE_STRING),
                                        'word_kh_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                        'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                                        'word_en_type': openapi.Schema(type=openapi.TYPE_STRING),
                                        'word_en_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                        'pronunciation_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                        'pronunciation_en': openapi.Schema(type=openapi.TYPE_STRING),
                                        'example_sentence_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                        'example_sentence_en': openapi.Schema(type=openapi.TYPE_STRING)
                                    }
                                ),
                                'created_at': openapi.Schema(
                                    type=openapi.TYPE_STRING,
                                    format=openapi.FORMAT_DATETIME
                                )
                            }
                        )
                    }
                )
            ),
            400: 'Bad Request - Invalid Input',
            401: 'Unauthorized - Invalid Authentication',
            404: 'Not Found - Word Does Not Exist'
        }
    )
    @debug_error
    def post(self, request):
        try:
            # Validate device ID
            device_id = self.validate_device_id(request)

            # Print debug information
            print("🔖 DEBUG: Creating Bookmark")
            print(f"🔑 Device ID: {device_id}")
            print(f"📦 Request Data: {request.data}")

            # Validate word_id is provided
            word_id = request.data.get('word_id')
            if not word_id:
                return Response({
                    'error': 'word_id is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Check if word exists
            try:
                word = Dictionary.objects.get(id=word_id)
            except Dictionary.DoesNotExist:
                return Response({
                    'error': f'Word with id {word_id} does not exist'
                }, status=status.HTTP_404_NOT_FOUND)

            # Check if bookmark already exists
            existing_bookmark = Bookmark.objects.filter(
                device_id=device_id,
                word=word
            ).first()

            if existing_bookmark:
                return Response({
                    'message': 'Bookmark already exists',
                    'bookmark_id': existing_bookmark.id
                }, status=status.HTTP_200_OK)

            # Create new bookmark
            bookmark = Bookmark.objects.create(
                device_id=device_id,
                word=word
            )

            # Serialize and return
            serializer = BookmarkSerializer(bookmark)
            return Response(serializer.data, status=status.HTTP_201_CREATED)

        except ValueError as ve:
            return Response({
                'error': str(ve)
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Log detailed error
            logger.error(f"Bookmark Creation Error: {str(e)}")
            print("❌ Bookmark Creation Error:")
            traceback.print_exc()

            return Response({
                'error': 'Failed to create bookmark',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Retrieve bookmarks for a device",
        tags=['mobile'],
        manual_parameters=[
            openapi.Parameter(
                'X-Device-ID',
                openapi.IN_HEADER,
                description="Unique Device Identifier",
                type=openapi.TYPE_STRING,
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
                description="Number of items per page",
                type=openapi.TYPE_INTEGER,
                default=10
            )
        ],
        responses={
            200: openapi.Response(
                description='Successfully Retrieved Bookmarks',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'bookmarks': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'word_details': openapi.Schema(
                                        type=openapi.TYPE_OBJECT,
                                        properties={
                                            'word_id': openapi.Schema(type=openapi.TYPE_INTEGER),
                                            'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_kh_type': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_kh_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_en_type': openapi.Schema(type=openapi.TYPE_STRING),
                                            'word_en_definition': openapi.Schema(type=openapi.TYPE_STRING),
                                            'pronunciation_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                            'pronunciation_en': openapi.Schema(type=openapi.TYPE_STRING),
                                            'example_sentence_kh': openapi.Schema(type=openapi.TYPE_STRING),
                                            'example_sentence_en': openapi.Schema(type=openapi.TYPE_STRING)
                                        }
                                    ),
                                    'created_at': openapi.Schema(
                                        type=openapi.TYPE_STRING,
                                        format=openapi.FORMAT_DATETIME
                                    )
                                }
                            )
                        ),
                        'total_bookmarks': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'page': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'per_page': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'total_pages': openapi.Schema(type=openapi.TYPE_INTEGER)
                    }
                )
            ),
            400: 'Bad Request - Invalid Input',
            401: 'Unauthorized - Invalid Authentication'
        }
    )
    @debug_error
    def get(self, request):
        """
        Retrieve bookmarks for a device
        """
        try:
            # Validate device ID
            device_id = self.validate_device_id(request)

            # Get bookmarks
            bookmarks = Bookmark.objects.filter(device_id=device_id)

            # Paginate
            page = int(request.query_params.get('page', 1))
            per_page = int(request.query_params.get('per_page', 10))

            start = (page - 1) * per_page
            end = start + per_page

            paginated_bookmarks = bookmarks[start:end]

            # Serialize bookmarks
            serializer = BookmarkSerializer(paginated_bookmarks, many=True)

            return Response({
                'bookmarks': serializer.data,
                'total_bookmarks': bookmarks.count(),
                'page': page,
                'per_page': per_page,
                'total_pages': (bookmarks.count() + per_page - 1) // per_page
            })

        except ValueError as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'error': 'An unexpected error occurred'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Remove a bookmark for a word",
        tags=['mobile'],
        manual_parameters=[
            openapi.Parameter(
                'X-Device-ID',
                openapi.IN_HEADER,
                description="Unique Device Identifier",
                type=openapi.TYPE_STRING,
                required=True
            )
        ],
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['word_id'],
            properties={
                'word_id': openapi.Schema(
                    type=openapi.TYPE_INTEGER,
                    description="ID of the dictionary entry to remove from bookmarks"
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='Bookmark Removed Successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Success message'
                        )
                    }
                )
            ),
            400: 'Bad Request - Invalid Input',
            401: 'Unauthorized - Invalid Authentication',
            404: 'Not Found - Bookmark Does Not Exist'
        }
    )
    @debug_error
    def delete(self, request):
        """
        Delete a bookmark
        """
        try:
            # Validate device ID
            device_id = self.validate_device_id(request)

            # Print debug information
            print("🔖 DEBUG: Deleting Bookmark")
            print(f"🔑 Device ID: {device_id}")
            print(f"📦 Request Data: {request.data}")

            # Validate word_id is provided
            word_id = request.data.get('word_id')
            if not word_id:
                return Response({
                    'error': 'word_id is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Find and delete the bookmark
            bookmark = Bookmark.objects.filter(
                device_id=device_id,
                word_id=word_id
            ).first()

            if not bookmark:
                return Response({
                    'error': 'Bookmark not found'
                }, status=status.HTTP_404_NOT_FOUND)

            bookmark.delete()
            return Response({
                'message': 'Bookmark deleted successfully'
            }, status=status.HTTP_200_OK)

        except ValueError as ve:
            return Response({
                'error': str(ve)
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Log detailed error
            logger.error(f"Bookmark Deletion Error: {str(e)}")
            print("❌ Bookmark Deletion Error:")
            traceback.print_exc()

            return Response({
                'error': 'Failed to delete bookmark',
                'details': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DictionarySyncAllView(APIView):
    """
    Comprehensive Endpoint for Full Dictionary Synchronization
    """
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_id='dictionary_sync_all',
        tags={'mobile'},
        operation_description="""
        Full Dictionary Synchronization Endpoint

        ### Example Requests:
        1. Default Sync:
        ```
        GET /dictionary/sync_all/
        ```

        2. Custom Pagination:
        ```
        GET /dictionary/sync_all/?page=2&per_page=500
        ```
        """,
        manual_parameters=[
            openapi.Parameter(
                'page',
                openapi.IN_QUERY,
                description="Page number for pagination (default: 1)",
                type=openapi.TYPE_INTEGER,
                default=1
            ),
            openapi.Parameter(
                'per_page',
                openapi.IN_QUERY,
                description="Number of entries per page (default: 1000, max: 2000)",
                type=openapi.TYPE_INTEGER,
                default=1000
            )
        ],
        responses={
            200: openapi.Response(
                description='Successful Dictionary Synchronization',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'entries': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'index': openapi.Schema(type=openapi.TYPE_INTEGER, description='Unique entry index'),
                                    'word_kh': openapi.Schema(type=openapi.TYPE_STRING, description='Khmer word'),
                                    'word_en': openapi.Schema(type=openapi.TYPE_STRING, description='English word'),
                                }
                            )
                        ),
                        'sync_metadata': openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                'total_entries': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'page': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'per_page': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'total_pages': openapi.Schema(type=openapi.TYPE_INTEGER),
                                'sync_id': openapi.Schema(type=openapi.TYPE_STRING),
                                'sync_timestamp': openapi.Schema(type=openapi.TYPE_STRING)
                            }
                        )
                    }
                )
            ),
            400: 'Bad Request - Invalid Parameters',
            429: 'Too Many Requests'
        }
    )
    @debug_error
    def get(self, request):
        # Generate unique sync request ID for tracking
        sync_id = str(uuid.uuid4())
        sync_timestamp = timezone.now().isoformat()

        try:
            # Validate and sanitize input parameters
            page = max(1, int(request.query_params.get('page', 1)))
            per_page = min(max(1, int(request.query_params.get('per_page', 1000))), 2000)

            # Create cache key for this specific sync request
            cache_key = f"sync_all_page_{page}_per_page_{per_page}"

            # Try to retrieve cached response
            cached_response = cache.get(cache_key)
            if cached_response and settings.DEBUG is False:
                logger.info(f"Serving cached sync all response - Sync ID: {sync_id}")
                return Response(cached_response)

            # Calculate pagination
            total_entries = Dictionary.objects.count()
            total_pages = (total_entries + per_page - 1) // per_page

            # Validate page number
            if page > total_pages:
                return Response({
                    'error': 'Page number exceeds total available pages',
                    'total_pages': total_pages
                }, status=status.HTTP_400_BAD_REQUEST)

            # Calculate start and end indices
            start = (page - 1) * per_page
            end = start + per_page

            # Fetch entries with optimized queryset
            entries = Dictionary.objects.order_by('index')[start:end]

            # Serialize entries
            serializer = DictionaryEntrySyncSerializer(entries, many=True)

            # Prepare response
            response_data = {
                'entries': serializer.data,
                'sync_metadata': {
                    'total_entries': total_entries,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': total_pages,
                    'sync_id': sync_id,
                    'sync_timestamp': sync_timestamp
                }
            }

            # Cache response (if not in debug mode)
            if settings.DEBUG is False:
                cache.set(
                    cache_key,
                    response_data,
                    timeout=3600  # Cache for 1 hour
                )

            # Log successful sync
            logger.info(f"Sync All Successful - Sync ID: {sync_id}, Page: {page}, Entries: {len(entries)}")

            return Response(response_data)

        except ValueError as ve:
            # Handle invalid parameter types
            logger.error(f"Sync All Error - Invalid Parameters: {str(ve)}")
            return Response({
                'error': 'Invalid parameters',
                'details': str(ve)
            }, status=status.HTTP_400_BAD_REQUEST)

        except Exception as e:
            # Catch-all for unexpected errors
            logger.error(f"Sync All Critical Error - Sync ID: {sync_id}, Error: {str(e)}")
            return Response({
                'error': 'Internal server error',
                'sync_id': sync_id
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DictionarySyncView(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_description="""
        Incremental Dictionary Synchronization Endpoint

        This endpoint allows mobile apps to:
        - Fetch new entries
        - Get updates to existing entries
        - Synchronize dictionary content

        Key Features:
        - Supports incremental sync
        - Returns only active and updated entries
        - Provides comprehensive metadata
        """,
        tags={'mobile'},
        manual_parameters=[
            openapi.Parameter(
                'last_sync_timestamp',
                openapi.IN_QUERY,
                description="Last Synchronization Timestamp (ISO format)",
                type=openapi.TYPE_STRING,
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
                default=500
            )
        ]
    )
    @debug_error
    def get(self, request):
        # Extract sync parameters
        last_sync_timestamp = request.query_params.get('last_sync_timestamp')
        page = int(request.query_params.get('page', 1))
        per_page = int(request.query_params.get('per_page', 500))

        # Validate last sync timestamp
        try:
            last_sync = timezone.datetime.fromisoformat(last_sync_timestamp)
        except (ValueError, TypeError):
            return Response({
                'error': 'Invalid timestamp format. Use ISO format.',
                'example': '2024-03-22T10:30:45.123456Z'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Query for updated and new entries
        updated_entries = Dictionary.objects.filter(
            Q(created_at__gt=last_sync) |  # New entries
            Q(updated_at__gt=last_sync),   # Updated existing entries
            is_active=True  # Only active entries
        ).order_by('updated_at')

        # Pagination
        total_entries = updated_entries.count()
        total_pages = (total_entries + per_page - 1) // per_page

        # Calculate start and end indices
        start = (page - 1) * per_page
        end = start + per_page
        paginated_entries = updated_entries[start:end]

        # Serialize entries
        serializer = DictionaryEntrySyncSerializer(paginated_entries, many=True)

        # Prepare response
        response_data = {
            'entries': serializer.data,
            'sync_metadata': {
                'total_entries': total_entries,
                'page': page,
                'per_page': per_page,
                'total_pages': total_pages,
                'last_sync_timestamp': last_sync_timestamp,
                'current_sync_timestamp': timezone.now().isoformat()
            }
        }

        return Response(response_data)

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

            if language in ['KH-EN', 'ALL']:
                field_conditions.extend([
                    Q(**{f'{mapped_field}__icontains': query})
                    for mapped_field in field_mapping[field] if 'kh' in mapped_field
                ])

            if language in ['EN-KH', 'ALL']:
                field_conditions.extend([
                    Q(**{f'{mapped_field}__icontains': query})
                    for mapped_field in field_mapping[field] if 'en' in mapped_field
                ])

            if field_conditions:
                search_conditions.append(reduce(operator.or_, field_conditions))

        return reduce(operator.or_, search_conditions) if search_conditions else Q()

    @swagger_auto_schema(
        operation_description="""
        Comprehensive Dictionary Search Endpoint

        This endpoint allows flexible searching across the dictionary with multiple parameters:

        Search Capabilities:
        - Search in Khmer and English words
        - Multiple search fields (words, definitions, example sentences)
        - Language direction filtering
        - Pagination support

        Language Options:
        - KH-EN: Search Khmer to English
        - EN-KH: Search English to Khmer
        - ALL: Search across both languages (default)

        Search Fields:
        - 'word': Search in word fields
        - 'definition': Search in definition fields
        - 'example_sentence': Search in example sentence fields

        Recommended Use Cases:
        1. Basic word lookup
        ```
        GET /api/dictionary/search/?query=hello
        ```
        2. Multilingual search
        ```
        GET /api/dictionary/search/?query=សួស្ដី&language=KH-EN&search_fields=word
        ```
        ```
        GET /api/dictionary/search/?query=hello&language=EN-KH&search_fields=word
        ```
        3. Comprehensive content search
        ```
        GET /api/dictionary/search/?query=eat&page=2&per_page=20
        ```
        4. Complex search
        ```
        GET /api/dictionary/search/?query=travel&language=ALL&search_fields=definition&search_fields=example_sentence
        ```
        """,
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
                enum=['KH-EN', 'EN-KH', 'ALL'],
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
                        'results': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(
                                type=openapi.TYPE_OBJECT,
                                properties={
                                    'id': openapi.Schema(
                                        type=openapi.TYPE_INTEGER,
                                        description='Unique identifier for dictionary entry'
                                    ),
                                    'word_kh': openapi.Schema(
                                        type=openapi.TYPE_STRING,
                                        description='Khmer word'
                                    ),
                                    'word_en': openapi.Schema(
                                        type=openapi.TYPE_STRING,
                                        description='English word'
                                    ),
                                    'word_kh_type': openapi.Schema(
                                        type=openapi.TYPE_STRING,
                                        description='Khmer word type (noun, verb, etc.)'
                                    ),
                                    'word_en_type': openapi.Schema(
                                        type=openapi.TYPE_STRING,
                                        description='English word type (noun, verb, etc.)'
                                    ),
                                    'word_kh_definition': openapi.Schema(
                                        type=openapi.TYPE_STRING,
                                        description='Definition of the word in Khmer'
                                    ),
                                    'word_en_definition': openapi.Schema(
                                        type=openapi.TYPE_STRING,
                                        description='Definition of the word in English'
                                    )
                                }
                            )
                        ),
                        'total_results': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='Total number of search results'
                        ),
                        'page': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='Current page number'
                        ),
                        'total_pages': openapi.Schema(
                            type=openapi.TYPE_INTEGER,
                            description='Total number of pages'
                        ),
                        'search_query': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Original search query'
                        ),
                        'search_language': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Language direction used for search'
                        ),
                        'search_fields': openapi.Schema(
                            type=openapi.TYPE_ARRAY,
                            items=openapi.Schema(type=openapi.TYPE_STRING),
                            description='Fields used in the search'
                        )
                    }
                )
            ),
            400: openapi.Response(
                description='Bad Request',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(
                            type=openapi.TYPE_STRING,
                            description='Error message explaining the bad request'
                        )
                    }
                )
            )
        }
    )
    @debug_error
    @track_search_performance
    def get(self, request):
        # Extract parameters
        query = request.query_params.get('query', '').strip()
        language = request.query_params.get('language', 'ALL')
        search_fields = request.query_params.getlist('search_fields') or self.DEFAULT_SEARCH_FIELDS
        page = int(request.query_params.get('page', 1))
        per_page = int(request.query_params.get('per_page', 10))

        # Validate input
        if not query:
            return Response({
                'error': 'Search query is required'
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
            'results': DictionaryEntrySerializer(paginated_entries, many=True).data,
            'total_results': total_results,
            'page': page,
            'total_pages': total_pages,
            'search_query': query,
            'search_language': language,
            'search_fields': search_fields
        }

        # Cache results
        cache.set(cache_key, response_data, timeout=3600)

        return Response(response_data)

class StagingBulkImportView(APIView):
    parser_classes = (MultiPartParser, FormParser)
    permission_classes = [IsAuthenticated]

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
                        'failed_entries': openapi.Schema(type=openapi.TYPE_ARRAY,
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

            # Validate column names exactly match the template
            expected_columns = [
                'id', 'word_kh', 'word_kh_type', 'word_kh_definition',
                'word_en', 'word_en_type', 'word_en_definition',
                'pronunciation_kh', 'pronunciation_en',
                'example_sentence_kh', 'example_sentence_en'
            ]

            # Strict column name validation
            if list(df.columns) != expected_columns:
                return Response({
                    'error': 'Column names do not match the template. Do not modify headers!',
                    'expected_columns': expected_columns,
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

                    # Use existing create serializer for validation
                    serializer = StagingEntryCreateSerializer(
                        data=staging_data,
                        context={'request': request}
                    )

                    if serializer.is_valid():
                        serializer.save()
                        successful_entries.append(serializer.data)
                    else:
                        failed_entries.append({
                            'row': index + 2,  # Excel rows start at 1, add header
                            'errors': serializer.errors
                        })

                except Exception as e:
                    failed_entries.append({
                        'row': index + 2,
                        'errors': str(e)
                    })

            return Response({
                'total_entries': len(df),
                'successful_entries': len(successful_entries),
                'failed_entries': failed_entries
            })

        except Exception as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )

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
