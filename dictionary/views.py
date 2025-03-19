# dictionary/views.py
from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
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
        Endpoint to fetch all dictionary records for mobile app initial sync
        """
        # Fetch all records without any filtering
        queryset = self.get_queryset()

        # Serialize all records
        serializer = self.get_serializer(queryset, many=True)

        # Return full response
        return Response({
            'total_records': queryset.count(),
            'words': serializer.data
        })
