# dictionary/views.py
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import pandas as pd
import io

from .models import StagingDictionaryEntry, DictionaryEntry, Bookmark
from .serializers import StagingDictionaryEntrySerializer, DictionaryEntrySerializer, BookmarkSerializer
from users.custom_auth import DeviceJWTAuthentication
from users.models import MobileDevice

class StagingDictionaryEntryViewSet(viewsets.ModelViewSet):
    queryset = StagingDictionaryEntry.objects.all()
    serializer_class = StagingDictionaryEntrySerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Create a new staging dictionary entry",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['word_kh', 'word_kh_type', 'word_kh_definition', 'word_en', 'word_en_type', 'word_en_definition'],
            properties={
                'word_kh': openapi.Schema(type=openapi.TYPE_STRING, description='Khmer word'),
                'word_kh_type': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Khmer word type',
                    enum=['នាម', 'កិរិយាសព្ទ', 'គុណនាម', 'គុណកិរិយា', 'សព្វនាម', 'ធ្នាក់', 'ឈ្នាប់', 'ឧទានសព្ទ']
                ),
                'word_kh_definition': openapi.Schema(type=openapi.TYPE_STRING, description='Khmer word definition'),
                'word_en': openapi.Schema(type=openapi.TYPE_STRING, description='English word'),
                'word_en_type': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='English word type',
                    enum=['NOUN', 'VERB', 'ADJECTIVE', 'ADVERB', 'PRONOUN', 'PREPOSITION', 'CONJUNCTION', 'INTERJECTION']
                ),
                'word_en_definition': openapi.Schema(type=openapi.TYPE_STRING, description='English word definition'),
                'pronunciation_kh': openapi.Schema(type=openapi.TYPE_STRING, description='Khmer word pronunciation'),
                'pronunciation_en': openapi.Schema(type=openapi.TYPE_STRING, description='English word pronunciation'),
                'example_sentence_kh': openapi.Schema(type=openapi.TYPE_STRING, description='Example sentence in Khmer'),
                'example_sentence_en': openapi.Schema(type=openapi.TYPE_STRING, description='Example sentence in English')
            }
        ),
        responses={
            201: openapi.Response(
                description='Staging entry created successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'word_kh': openapi.Schema(type=openapi.TYPE_STRING),
                        'word_en': openapi.Schema(type=openapi.TYPE_STRING),
                        'review_status': openapi.Schema(type=openapi.TYPE_STRING),
                        'created_by_username': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            400: openapi.Response(
                description='Validation error',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    def create(self, request, *args, **kwargs):
        return super().create(request, *args, **kwargs)

    @swagger_auto_schema(
        operation_description="Approve a staging dictionary entry",
        responses={
            201: openapi.Response(
                description='Entry approved and added to dictionary',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'entry_id': openapi.Schema(type=openapi.TYPE_INTEGER)
                    }
                )
            ),
            400: openapi.Response(
                description='Approval error',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    @action(detail=True, methods=['POST'], permission_classes=[IsAdminUser])
    def approve(self, request, pk=None):
        """
        Approve a staging entry and move it to the main dictionary
        """
        staging_entry = self.get_object()

        # Prevent re-approval
        if staging_entry.review_status != 'PENDING':
            return Response({
                'error': 'Entry is not in pending status'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            # Calculate next index
            next_index = DictionaryEntry.objects.count() + 1

            # Create a new entry in the main dictionary
            dictionary_entry = DictionaryEntry.objects.create(
                word_kh=staging_entry.word_kh,
                word_kh_type=staging_entry.word_kh_type,
                word_kh_definition=staging_entry.word_kh_definition,
                word_en=staging_entry.word_en,
                word_en_type=staging_entry.word_en_type,
                word_en_definition=staging_entry.word_en_definition,
                index=next_index,
                created_by=staging_entry.created_by,
                pronunciation_kh=staging_entry.pronunciation_kh,
                pronunciation_en=staging_entry.pronunciation_en,
                example_sentence_kh=staging_entry.example_sentence_kh,
                example_sentence_en=staging_entry.example_sentence_en
            )

            # Update staging entry status
            staging_entry.review_status = 'APPROVED'
            staging_entry.reviewed_by = request.user
            staging_entry.reviewed_at = timezone.now()
            staging_entry.save()

            return Response({
                'message': 'Entry approved and added to dictionary',
                'entry_id': dictionary_entry.id,
                'created_by': dictionary_entry.created_by.username,
                'reviewed_by': request.user.username
            }, status=status.HTTP_201_CREATED)

        except Exception as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @swagger_auto_schema(
        operation_description="Reject a staging dictionary entry",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['rejection_reason'],
            properties={
                'rejection_reason': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description='Reason for rejecting the entry'
                )
            }
        ),
        responses={
            200: openapi.Response(
                description='Entry rejected successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'message': openapi.Schema(type=openapi.TYPE_STRING),
                        'rejection_reason': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            ),
            400: openapi.Response(
                description='Rejection error',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'error': openapi.Schema(type=openapi.TYPE_STRING)
                    }
                )
            )
        }
    )
    @action(detail=True, methods=['POST'], permission_classes=[IsAdminUser])
    def reject(self, request, pk=None):
        """
        Reject a staging entry
        """
        staging_entry = self.get_object()

        # Prevent re-rejection
        if staging_entry.review_status != 'PENDING':
            return Response({
                'error': 'Entry is not in pending status'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Get rejection reason from request
        rejection_reason = request.data.get('rejection_reason', 'No reason provided')

        # Update staging entry status
        staging_entry.review_status = 'REJECTED'
        staging_entry.reviewed_by = request.user
        staging_entry.reviewed_at = timezone.now()
        staging_entry.rejection_reason = rejection_reason
        staging_entry.save()

        return Response({
            'message': 'Entry rejected',
            'rejection_reason': rejection_reason
        })

class DictionaryEntryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = DictionaryEntry.objects.all()
    serializer_class = DictionaryEntrySerializer
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="List dictionary entries with optional filtering",
        manual_parameters=[
            openapi.Parameter(
                'word_kh',
                openapi.IN_QUERY,
                description="Filter by Khmer word",
                type=openapi.TYPE_STRING
            ),
            openapi.Parameter(
                'word_en',
                openapi.IN_QUERY,
                description="Filter by English word",
                type=openapi.TYPE_STRING
            )
        ],
        responses={
            200: openapi.Response(
                description='List of dictionary entries',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'count': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'next': openapi.Schema(type=openapi.TYPE_STRING),
                        'previous': openapi.Schema(type=openapi.TYPE_STRING),
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
                                    'index': openapi.Schema(type=openapi.TYPE_INTEGER)
                                }
                            )
                        )
                    }
                )
            )
        }
    )
    def list(self, request, *args, **kwargs):
        return super().list(request, *args, **kwargs)

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
    def post(self, request):
        """
        Add a bookmark for a word
        """
        try:
            # Validate device ID
            device_id = self.validate_device_id(request)

            # Get word ID from request
            word_id = request.data.get('word_id')
            if not word_id:
                return Response({
                    'error': 'Word ID is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Find the word
            try:
                word = DictionaryEntry.objects.get(id=word_id)
            except DictionaryEntry.DoesNotExist:
                return Response({
                    'error': 'Word not found'
                }, status=status.HTTP_404_NOT_FOUND)

            # Create or get bookmark
            bookmark, created = Bookmark.objects.get_or_create(
                device_id=device_id,
                word=word
            )

            # Serialize and return word details
            serializer = BookmarkSerializer(bookmark)
            return Response({
                'message': 'Bookmark added successfully' if created else 'Bookmark already exists',
                'bookmark': serializer.data
            }, status=status.HTTP_201_CREATED if created else status.HTTP_200_OK)

        except ValueError as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'error': 'An unexpected error occurred'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @swagger_auto_schema(
        operation_description="Retrieve bookmarks for a device",
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
    def delete(self, request):
        """
        Remove a bookmark
        """
        try:
            # Validate device ID
            device_id = self.validate_device_id(request)

            # Get word ID to remove
            word_id = request.data.get('word_id')
            if not word_id:
                return Response({
                    'error': 'Word ID is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Find and delete bookmark
            try:
                bookmark = Bookmark.objects.get(
                    device_id=device_id,
                    word_id=word_id
                )
                bookmark.delete()
                return Response({
                    'message': 'Bookmark removed successfully'
                }, status=status.HTTP_200_OK)
            except Bookmark.DoesNotExist:
                return Response({
                    'error': 'Bookmark not found'
                }, status=status.HTTP_404_NOT_FOUND)

        except ValueError as e:
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            return Response({
                'error': 'An unexpected error occurred'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
