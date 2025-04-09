# dictionary/serializers.py
from rest_framework import serializers
from .models import Staging, Dictionary, WordType, Bookmark
from django.utils import timezone
from django.db.models import Q

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
            'word_kh',
            'word_en',
            'word_kh_type',
            'word_en_type',
            'word_kh_definition',
            'word_en_definition',
            'pronunciation_kh',
            'pronunciation_en',
            'example_sentence_kh',
            'example_sentence_en'
        ]
        extra_kwargs = {
            'pronunciation_kh': {'required': False},
            'pronunciation_en': {'required': False},
            'example_sentence_kh': {'required': False},
            'example_sentence_en': {'required': False}
        }

    def create(self, validated_data):
        # Automatically set created_by and review_status
        validated_data['created_by'] = self.context['request'].user
        validated_data['review_status'] = 'PENDING'
        return super().create(validated_data)

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

class BookmarkSerializer(serializers.ModelSerializer):
    word_details = serializers.SerializerMethodField()

    class Meta:
        model = Bookmark
        fields = ["id", "word"]

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
            "created_at": word.created_at.isoformat()
            # "pronunciation_kh": word.pronunciation_kh,
            # "pronunciation_en": word.pronunciation_en,
            # "example_sentence_kh": word.example_sentence_kh,
            # "example_sentence_en": word.example_sentence_en
        }


class DictionaryEntrySerializer(serializers.ModelSerializer):
    word_related = serializers.SerializerMethodField() #change word_related to relateWords
    is_bookmark = serializers.SerializerMethodField()

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
            'is_bookmark',
            'is_parent',
            'word_related' #change word_related to relateWords
        ]

    def get_word_related(self, obj): #change word_related to relateWords
        # If is_parent is True, find related words
        if obj.is_parent:
            # Find words that contain the parent word
            related_words = Dictionary.objects.filter(
                Q(word_en__contains=obj.word_en) |
                Q(word_kh__contains=obj.word_kh)
            ).exclude(id=obj.id)

            if related_words.exists():
                return [
                    {
                        'related_id': rw.id,
                        'related_word_kh': rw.word_kh,
                        'related_word_en': rw.word_en,
                        # 'word_kh_type': rw.word_kh_type,
                        # 'word_en_type': rw.word_en_type,
                        # 'word_kh_definition': rw.word_kh_definition,
                        # 'word_en_definition': rw.word_en_definition,
                        # 'is_bookmark': 0,
                        # 'is_child': True
                    } for rw in related_words
                ]

            return None

        return None

    def get_is_bookmark(self, obj):
        request = self.context.get('request')
        if not request:
            return 0

        device_id = request.headers.get('X-Device-ID')
        if not device_id:
            return 0

        from .models import Bookmark
        bookmark_exists = Bookmark.objects.filter(
            device_id=device_id,
            word=obj
        ).exists()

        return 1 if bookmark_exists else 0

    def validate(self, data):
        is_parent = data.get('is_parent', self.instance.is_parent if self.instance else False)
        is_child = data.get('is_child', self.instance.is_child if self.instance else False)

        if is_parent and is_child:
            raise serializers.ValidationError("A word cannot be both parent and child simultaneously.")

        return data

    def get_created_by(self, obj):
        return obj.created_by.username if obj.created_by else None

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

class DictionarySearchSerializer(serializers.Serializer):
    # Custom serializer for search results with additional metadata
    results = DictionaryEntrySerializer(many=True)
    total_results = serializers.IntegerField()
    page = serializers.IntegerField()
    total_pages = serializers.IntegerField()
    search_query = serializers.CharField()
    search_language = serializers.CharField()
    search_fields = serializers.ListField(child=serializers.CharField())


class RelatedWordSerializer(serializers.ModelSerializer):
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
            'is_parent',
            'is_child'
        ]
