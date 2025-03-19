# dictionary/serializers.py
from rest_framework import serializers
from .models import Dictionary, WordType

class DictionarySerializer(serializers.ModelSerializer):
    word_type_en = serializers.SerializerMethodField()
    word_type_kh = serializers.SerializerMethodField()
    created_by = serializers.SerializerMethodField()
    updated_by = serializers.SerializerMethodField()

    class Meta:
        model = Dictionary
        fields = [
            'id',
            'word_kh',
            'word_en',
            'definition_kh',
            'definition_en',
            'word_type_en',
            'word_type_kh',
            'word_type_en',
            'word_type_kh',
            'created_by',
            'updated_by',
            'created_at',
            'updated_at'
        ]
        read_only_fields = [
            'id',
            'created_at',
            'updated_at'
        ]

    def get_word_type_en_display(self, obj):
        return obj.get_word_type_en_display()

    def get_word_type_kh_display(self, obj):
        return obj.get_word_type_kh_display()

    def get_created_by_username(self, obj):
        return obj.created_by.username if obj.created_by else None

    def get_updated_by_username(self, obj):
        return obj.updated_by.username if obj.updated_by else None

    def create(self, validated_data):

        en_type = validated_data.get('word_type_en')
        kh_type = validated_data.get('word_type_kh')

        type_map = dict(zip(
            [t[0] for t in WordType.WORD_TYPE_CHOICES_EN],
            [t[0] for t in WordType.WORD_TYPE_CHOICES_KH]
        ))

        if type_map.get(en_type) != kh_type:
            raise serializers.ValidationError("Word types must match between English and Khmer")

        validated_data['created_by'] = self.context['request'].user
        return super().create(validated_data)

    def update(self, instance, validated_data):
        validated_data['updated_by'] = self.context['request'].user
        return super().update(instance, validated_data)
