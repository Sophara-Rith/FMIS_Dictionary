# dictionary/serializers.py
from rest_framework import serializers
from .models import Staging, Dictionary, WordType, Bookmark
from django.utils import timezone

class StagingDictionaryEntrySerializer(serializers.ModelSerializer):
    created_by = serializers.SerializerMethodField()
    reviewed_by = serializers.SerializerMethodField()

    class Meta:
        model = Staging
        fields = '__all__'
        read_only_fields = [
            'created_at',
            'reviewed_at',
            'review_status',
            'created_by',
            'reviewed_by'
        ]

    def get_created_by(self, obj):
        # Return username instead of user ID
        return obj.created_by.username if obj.created_by else None

    def get_reviewed_by(self, obj):
        # Return username instead of user ID
        return obj.reviewed_by.username if obj.reviewed_by else None

    def validate(self, data):
        # Validate word type consistency
        en_type = data.get('word_en_type')
        kh_type = data.get('word_kh_type')

        # Create mapping between EN and KH word types
        type_map = dict(zip(
            [t[0] for t in WordType.WORD_TYPE_CHOICES_EN],
            [t[0] for t in WordType.WORD_TYPE_CHOICES_KH]
        ))

        if en_type and kh_type and type_map.get(en_type) != kh_type:
            raise serializers.ValidationError({
                "word_type": "English and Khmer word types must match"
            })

        return data

    def create(self, validated_data):
        # Automatically set created_by to current user
        validated_data['created_by'] = self.context['request'].user
        validated_data['review_status'] = 'PENDING'
        return super().create(validated_data)

class DictionaryEntrySerializer(serializers.ModelSerializer):
    created_by = serializers.SerializerMethodField()

    class Meta:
        model = Dictionary
        fields = [
            'index',
            'word_kh',
            'word_en',
            'word_kh_type',
            'word_en_type',
            'word_kh_definition',
            'word_en_definition',
            'example_sentence_kh',
            'example_sentence_en'
        ]
        read_only_fields = ['created_at', 'index', 'created_by']

    def get_created_by(self, obj):
        return obj.created_by.username if obj.created_by else None

class StagingEntrySerializer(serializers.ModelSerializer):
    created_by = serializers.SerializerMethodField()
    reviewed_by = serializers.SerializerMethodField()

    class Meta:
        model = Staging
        fields = '__all__'
        read_only_fields = [
            'created_at',
            'review_status',
            'created_by',
            'reviewed_by'
        ]

    def get_created_by(self, obj):
        return obj.created_by.username if obj.created_by else None

    def get_reviewed_by(self, obj):
        return obj.reviewed_by.username if obj.reviewed_by else None

class StagingEntryCreateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Staging
        fields = [
            'id', 'word_kh', 'word_kh_type', 'word_kh_definition',
            'word_en', 'word_en_type', 'word_en_definition',
            'pronunciation_kh', 'pronunciation_en',
            'example_sentence_kh', 'example_sentence_en'
        ]
        extra_kwargs = {
            'id': {'read_only': True},  # Make id read-only
            'pronunciation_kh': {'required': False},
            'pronunciation_en': {'required': False},
            'example_sentence_kh': {'required': False},
            'example_sentence_en': {'required': False}
        }

    def validate(self, data):
        """
        Automatically map Khmer word type to English word type
        """
        # Check if Khmer word type is provided
        kh_type = data.get('word_kh_type')

        if kh_type:
            # Automatically map Khmer type to English type
            en_type = WordType.WORD_TYPE_MAP.get(kh_type)

            if en_type:
                # Set the English word type automatically
                data['word_en_type'] = en_type

        # Existing validation logic
        required_fields = [
            'word_kh',
            'word_kh_type',
            'word_kh_definition',
            'word_en',
            'word_en_type',
            'word_en_definition'
        ]

        for field in required_fields:
            if not data.get(field):
                raise serializers.ValidationError({
                    field: f"{field.replace('_', ' ').title()} is required"
                })

        return data

    def create(self, validated_data):
        # Automatically set created_by to current user
        validated_data['created_by'] = self.context['request'].user
        validated_data['review_status'] = 'PENDING'
        return super().create(validated_data)

class BookmarkSerializer(serializers.ModelSerializer):
    word_details = serializers.SerializerMethodField()

    class Meta:
        model = Bookmark
        fields = ['word_details', 'created_at']

    def get_word_details(self, obj):
        word = obj.word
        return {
            "word_id": word.id,
            "word_kh": word.word_kh,
            "word_en": word.word_en,
            "word_en_type": word.word_en_type,
            "word_kh_type": word.word_kh_type,
            "word_kh_definition": word.word_kh_definition,
            "word_en_definition": word.word_en_definition,
            # "pronunciation_kh": word.pronunciation_kh,
            # "pronunciation_en": word.pronunciation_en,
            # "example_sentence_kh": word.example_sentence_kh,
            # "example_sentence_en": word.example_sentence_en
        }

class DictionaryEntrySyncSerializer(serializers.ModelSerializer):
    sync_status = serializers.SerializerMethodField()

    class Meta:
        model = Dictionary
        fields = [
            'id',
            'word_kh',
            'word_en',
            'word_kh_type',
            'word_en_type',
            'word_kh_definition',
            'word_en_definition',
            'example_sentence_kh',
            'example_sentence_en',
            'created_at',
            'updated_at',
            'sync_status'
        ]

    def get_sync_status(self, obj):
        """
        Determine sync status of the entry
        """
        request = self.context.get('request')
        last_sync = request.query_params.get('last_sync_timestamp')

        if last_sync:
            last_sync_time = timezone.datetime.fromisoformat(last_sync)

            if obj.created_at > last_sync_time:
                return 'NEW'
            elif obj.updated_at > last_sync_time:
                return 'UPDATED'

        return 'UNCHANGED'

class DictionaryEntrySerializer(serializers.ModelSerializer):
    class Meta:
        model = Dictionary
        fields = [
            'id',
            'word_kh',
            'word_en',
            'word_kh_type',
            'word_en_type',
            'word_kh_definition',
            'word_en_definition',
            'example_sentence_kh',
            'example_sentence_en'
        ]

class DictionarySearchSerializer(serializers.Serializer):
    # Custom serializer for search results with additional metadata
    results = DictionaryEntrySerializer(many=True)
    total_results = serializers.IntegerField()
    page = serializers.IntegerField()
    total_pages = serializers.IntegerField()
    search_query = serializers.CharField()
    search_language = serializers.CharField()
    search_fields = serializers.ListField(child=serializers.CharField())
