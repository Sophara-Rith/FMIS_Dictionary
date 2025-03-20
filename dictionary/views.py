# dictionary/views.py
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from django.utils.dateparse import parse_datetime
from .models import Dictionary
from .serializers import DictionarySerializer

class DictionaryViewSet(viewsets.ReadOnlyModelViewSet):
    queryset = Dictionary.objects.all().only(
        'id', 'word_kh', 'word_en',
        'definition_kh', 'definition_en',
        'word_type_en', 'word_type_kh'
    )
    serializer_class = DictionarySerializer
    permission_classes = [permissions.IsAuthenticated]

    @action(detail=False, methods=['GET'])
    def sync_all(self, request):
        """
        Endpoint to fetch all dictionary records for mobile app initial sync. Use for first time sync.
        """
        # Fetch all records without filter
        queryset = self.get_queryset()

        # Serialize all records
        serializer = self.get_serializer(queryset, many=True)

        # Return full response
        return Response({
            'total_records': queryset.count(),
            'words': serializer.data
        })

    @action(detail=False, methods=['GET'])
    def sync(self, request):
        """
        Fetch new or updated dictionary entries since last synchronization.
        """
        last_sync = request.query_params.get('last_sync')

        if last_sync:
            try:
                last_sync_datetime = parse_datetime(last_sync)
                queryset = Dictionary.objects.filter(updated_at__gt=last_sync_datetime)
            except ValueError:
                return Response({
                    'error': 'Invalid timestamp format. Use ISO format.'
                }, status=400)
        else:
            queryset = Dictionary.objects.all()

        serializer = self.get_serializer(queryset, many=True)

        return Response({
            'total_records': queryset.count(),
            'words': serializer.data,
            'sync_timestamp': timezone.now().isoformat()
        })
