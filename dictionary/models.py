# dictionary/models.py
import json
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.validators import MinLengthValidator
from django.core.exceptions import ValidationError

class WordType:
    WORD_TYPE_CHOICES_EN = [
        ('NOUN', 'Noun'),
        ('VERB', 'Verb'),
        ('ADJECTIVE', 'Adjective'),
        ('ADVERB', 'Adverb'),
        ('PRONOUN', 'Pronoun'),
        ('PREPOSITION', 'Preposition'),
        ('CONJUNCTION', 'Conjunction'),
        ('INTERJECTION', 'Interjection')
    ]

    WORD_TYPE_CHOICES_KH = [
        ('នាម', 'Noun'),
        ('កិរិយាសព្ទ', 'Verb'),
        ('គុណនាម', 'Adjective'),
        ('គុណកិរិយា', 'Adverb'),
        ('សព្វនាម', 'Pronoun'),
        ('ធ្នាក់', 'Preposition'),
        ('ឈ្នាប់', 'Conjunction'),
        ('ឧទានសព្ទ', 'Interjection')
    ]

    WORD_TYPE_MAP = {
        'នាម': 'NOUN',
        'កិរិយាសព្ទ': 'VERB',
        'គុណនាម': 'ADJECTIVE',
        'គុណកិរិយា': 'ADVERB',
        'សព្វនាម': 'PRONOUN',
        'ធ្នាក់': 'PREPOSITION',
        'ឈ្នាប់': 'CONJUNCTION',
        'ឧទានសព្ទ': 'INTERJECTION'
    }

    @classmethod
    def get_en_type(cls, kh_type):
        """
        Safely get English type from Khmer type

        Args:
            kh_type (str): Khmer word type

        Returns:
            str: Corresponding English word type or None
        """
        return cls.WORD_TYPE_MAP.get(kh_type)

class Staging(models.Model):
    REVIEW_STATUS_CHOICES = [
        ('PENDING', 'Pending Review'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected')
    ]

    LANGUAGE_CHOICES = [
        ('KH-EN', 'Khmer to English'),
        ('EN-KH', 'English to Khmer')
    ]

    id = models.BigAutoField(primary_key=True)

    word_kh = models.CharField(
        max_length=255,
        verbose_name='Khmer Word',
        validators=[MinLengthValidator(1, "Khmer word cannot be empty")]
    )
    word_en = models.CharField(
        max_length=255,
        verbose_name='English Word',
        validators=[MinLengthValidator(1, "English word cannot be empty")]
    )

    word_kh_type = models.CharField(
        max_length=50,
        choices=WordType.WORD_TYPE_CHOICES_KH,
        verbose_name='Khmer Word Type'
    )
    word_en_type = models.CharField(
        max_length=20,
        choices=WordType.WORD_TYPE_CHOICES_EN,
        verbose_name='English Word Type'
    )

    word_kh_definition = models.TextField(
        verbose_name='Khmer Word Definition'
    )
    word_en_definition = models.TextField(
        verbose_name='English Word Definition'
    )

    pronunciation_kh = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        verbose_name='Khmer Pronunciation'
    )
    pronunciation_en = models.CharField(
        max_length=255,
        null=True,
        blank=True,
        verbose_name='English Pronunciation'
    )
    example_sentence_kh = models.TextField(
        max_length=255,
        null=True,
        blank=True,
        verbose_name='Example Sentence in Khmer'
    )
    example_sentence_en = models.TextField(
        max_length=255,
        null=True,
        blank=True,
        verbose_name='Example Sentence in English'
    )

    created_at = models.DateTimeField(default=timezone.now)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='staging_entries',
        null=True
    )

    reviewed_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='reviewed_staging_entries',
        null=True,
        blank=True
    )

    review_status = models.CharField(
        max_length=20,
        choices=REVIEW_STATUS_CHOICES,
        default='PENDING'
    )

    rejection_reason = models.TextField(
        null=True,
        blank=True,
        verbose_name='Reason for Rejection'
    )

    def reject(self, user, reason):
        """
        Method to handle rejection of staging entry
        """
        self.review_status = 'REJECTED'
        self.rejected_at = timezone.now()
        self.rejected_by = user
        self.rejection_reason = reason
        self.save()

    is_parent = models.BooleanField(default=False)
    is_child = models.BooleanField(default=False)

    class Meta:
        verbose_name_plural = 'Staging Dictionary Entries'
        unique_together = [['word_kh', 'word_en']]
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['-id']),
            models.Index(fields=['is_parent']),
            models.Index(fields=['is_child']),
            models.Index(fields=['created_by_id']),
            models.Index(fields=['created_at']),
            models.Index(fields=['review_status'])
        ]

    def set_action_details(self, data):
        """Helper method to set action details"""
        self.action_details = json.dumps(data)

    def get_action_details(self):
        """Helper method to retrieve action details"""
        return json.loads(self.action_details) if self.action_details else {}

    def __str__(self):
        return f"{self.word_kh} ({self.word_en})"

class Dictionary(models.Model):
    # Existing fields
    id = models.AutoField(primary_key=True)
    word_kh = models.CharField(max_length=255)
    word_en = models.CharField(max_length=255)
    word_kh_type = models.CharField(max_length=50)
    word_en_type = models.CharField(max_length=50)
    word_kh_definition = models.TextField()
    word_en_definition = models.TextField()

    # Optional fields
    pronunciation_kh = models.CharField(max_length=255, null=True, blank=True)
    pronunciation_en = models.CharField(max_length=255, null=True, blank=True)
    example_sentence_kh = models.TextField(null=True, blank=True)
    example_sentence_en = models.TextField(null=True, blank=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        related_name='dictionary_entries'
    )
    index = models.IntegerField(unique=True)

    is_parent = models.BooleanField(default=False)
    is_child = models.BooleanField(default=False)

    deleted_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='deleted_dictionary_entries'
    )
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)

    def soft_delete(self, user):
        """
        Soft delete method to mark entry as deleted
        """
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.deleted_by = user
        self.save()

    def clean(self):
        if self.is_parent and self.is_child:
            raise ValidationError("A word cannot be both parent and child simultaneously.")

    def save(self, *args, **kwargs):
        self.full_clean()
        return super().save(*args, **kwargs)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['index', 'word_en'],
                name='unique_dictionary_index'
            )
        ]
        indexes = [
            models.Index(fields=['index']),
            models.Index(fields=['word_kh', 'word_en']),
            models.Index(fields=['is_parent']),
            models.Index(fields=['is_child'])
        ]

    def __str__(self):
        return f"{self.word_kh} ({self.word_en})"

class RelatedWord(models.Model):
    RELATIONSHIP_CHOICES = [
        ('DERIVATIVE', 'Derivative'),
        ('COMPOUND', 'Compound Word'),
        ('PHRASE', 'Phrase'),
        ('OTHER', 'Other')
    ]

    parent_word = models.ForeignKey(
        'Dictionary',
        on_delete=models.CASCADE,
        related_name='child_words'
    )
    child_word = models.ForeignKey(
        'Dictionary',
        on_delete=models.CASCADE,
        related_name='parent_words'
    )
    relationship_type = models.CharField(
        max_length=50,
        choices=RELATIONSHIP_CHOICES,
        default='OTHER'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('parent_word', 'child_word')
        indexes = [
            models.Index(fields=['parent_word']),
            models.Index(fields=['child_word'])
        ]

    def __str__(self):
        return f"{self.parent_word.word_en} -> {self.child_word.word_en}"

class Bookmark(models.Model):
    device_id = models.CharField(max_length=255)
    word = models.ForeignKey(
        'Dictionary',
        on_delete=models.CASCADE,
        related_name='bookmarks'
    )
    created_at = models.DateTimeField(auto_now_add=True)
    last_accessed = models.DateTimeField(null=True, blank=True)
    access_count = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = ('device_id', 'word')
        indexes = [
            models.Index(fields=['device_id', 'created_at']),
            models.Index(fields=['last_accessed']),
            models.Index(fields=['access_count'])
        ]
        verbose_name_plural = 'Bookmarks'

    def __str__(self):
        return f"Bookmark: {self.word.word_kh} - Device: {self.device_id}"
