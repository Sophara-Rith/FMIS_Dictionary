# dictionary/serializers.py
from rest_framework import serializers
from .models import Staging, Dictionary, WordType, Bookmark

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
        fields = '__all__'
        read_only_fields = ['created_at', 'index', 'created_by']

    def get_created_by(self, obj):
        # Return username instead of user ID
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
            'word_kh', 'word_en',
            'word_kh_type', 'word_en_type',
            'word_kh_definition', 'word_en_definition',
            'pronunciation_kh', 'pronunciation_en',
            'example_sentence_kh', 'example_sentence_en'
        ]

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
            "word_kh_type": word.word_kh_type,
            "word_kh_definition": word.word_kh_definition,
            "word_en": word.word_en,
            "word_en_type": word.word_en_type,
            "word_en_definition": word.word_en_definition,
            "pronunciation_kh": word.pronunciation_kh,
            "pronunciation_en": word.pronunciation_en,
            "example_sentence_kh": word.example_sentence_kh,
            "example_sentence_en": word.example_sentence_en
        }

class DictionaryEntrySyncSerializer(serializers.ModelSerializer):
    """
    Serializer for dictionary entries synchronization
    """
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
            'pronunciation_kh',
            'pronunciation_en',
            'example_sentence_kh',
            'example_sentence_en',
            'created_at'
        ]
