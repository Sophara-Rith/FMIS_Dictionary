# dictionary/views.py
from rest_framework import status
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from rest_framework.throttling import UserRateThrottle
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.views import APIView
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import DictionaryEntry, StagingEntry, Bookmark, WordType
from .serializers import (
    DictionaryEntrySerializer,
    BookmarkSerializer,
    StagingEntrySerializer,
    StagingEntryCreateSerializer
)

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
    def get(self, request):
        # Get query parameters
        language = request.query_params.get('language')
        search = request.query_params.get('search')

        # Base queryset
        entries = DictionaryEntry.objects.all()

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
    def get(self, request, pk):
        try:
            entry = DictionaryEntry.objects.get(pk=pk)
            serializer = DictionaryEntrySerializer(entry)
            return Response(serializer.data)
        except DictionaryEntry.DoesNotExist:
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
    def get(self, request):
        entries = StagingEntry.objects.all()
        serializer = StagingEntrySerializer(entries, many=True)
        return Response(serializer.data)

class StagingEntryCreateView(APIView):
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(
        operation_description="Create a new staging entry for dictionary",
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            required=['word', 'definition', 'language'],
            properties={
                'word': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="The word to be added"
                ),
                'definition': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Definition of the word"
                ),
                'language': openapi.Schema(
                    type=openapi.TYPE_STRING,
                    description="Language of the entry (KH-EN or EN-KH)",
                    enum=['KH-EN', 'EN-KH']
                ),
                'examples': openapi.Schema(
                    type=openapi.TYPE_ARRAY,
                    items=openapi.Schema(type=openapi.TYPE_STRING),
                    description="Example usages of the word"
                )
            }
        ),
        responses={
            201: openapi.Response(
                description='Staging entry created successfully',
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        'id': openapi.Schema(type=openapi.TYPE_INTEGER),
                        'word': openapi.Schema(type=openapi.TYPE_STRING),
                        'definition': openapi.Schema(type=openapi.TYPE_STRING),
                        'submitted_by': openapi.Schema(type=openapi.TYPE_STRING),
                    }
                )
            ),
            400: 'Validation Error'
        }
    )
    def post(self, request):
        serializer = StagingEntryCreateSerializer(
            data=request.data,
            context={'request': request}
        )
        if serializer.is_valid():
            serializer.save()
            return Response(
                serializer.data,
                status=status.HTTP_201_CREATED
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
    def post(self, request, pk):
        try:
            staging_entry = StagingEntry.objects.get(pk=pk)

            # Create dictionary entry
            dictionary_entry = DictionaryEntry.objects.create(
                word=staging_entry.word,
                definition=staging_entry.definition,
                language=staging_entry.language,
                examples=staging_entry.examples
            )

            # Delete staging entry
            staging_entry.delete()

            return Response({
                'message': 'Entry approved and added to dictionary',
                'entry': DictionaryEntrySerializer(dictionary_entry).data
            }, status=status.HTTP_200_OK)
        except StagingEntry.DoesNotExist:
            return Response(
                {'error': 'Staging entry not found'},
                status=status.HTTP_404_NOT_FOUND
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
    def post(self, request, pk):
        try:
            staging_entry = StagingEntry.objects.get(pk=pk)

            # Optional: Log rejection reason
            reason = request.data.get('reason', 'No reason provided')

            # Delete staging entry
            staging_entry.delete()

            return Response({
                'message': 'Entry rejected and deleted',
                'reason': reason
            }, status=status.HTTP_200_OK)
        except StagingEntry.DoesNotExist:
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
    def get(self, request, pk):
        try:
            staging_entry = StagingEntry.objects.get(pk=pk)

            # Check if user is admin or the creator of the entry
            if not (request.user.is_staff or
                    staging_entry.created_by == request.user):
                return Response(
                    {'error': 'You are not authorized to view this entry'},
                    status=status.HTTP_403_FORBIDDEN
                )

            serializer = StagingEntrySerializer(staging_entry)
            return Response(serializer.data)
        except StagingEntry.DoesNotExist:
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
    def put(self, request, pk):
        try:
            staging_entry = StagingEntry.objects.get(pk=pk)

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
        except StagingEntry.DoesNotExist:
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
    def delete(self, request, pk):
        try:
            staging_entry = StagingEntry.objects.get(pk=pk)

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
        except StagingEntry.DoesNotExist:
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
        tags=['Mobile'],
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
        tags=['Mobile'],
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
        tags=['Mobile'],
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
