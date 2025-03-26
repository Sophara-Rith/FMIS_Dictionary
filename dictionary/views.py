# dictionary/views.py
from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, IsAdminUser
from rest_framework.response import Response
from django.utils import timezone
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
import pandas as pd
import io

from .models import StagingDictionaryEntry, DictionaryEntry
from .serializers import StagingDictionaryEntrySerializer, DictionaryEntrySerializer

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
