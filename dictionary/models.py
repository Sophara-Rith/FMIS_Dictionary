# dictionary/models.py
from django.db import models
from django.conf import settings
from django.utils import timezone
from django.core.validators import MinLengthValidator

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

    # Word Fields
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

    # Type Fields
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

    # Definition Fields
    word_kh_definition = models.TextField(
        verbose_name='Khmer Word Definition',
        validators=[MinLengthValidator(5, "Definition must be at least 5 characters")]
    )
    word_en_definition = models.TextField(
        verbose_name='English Word Definition',
        validators=[MinLengthValidator(5, "Definition must be at least 5 characters")]
    )

    # Tracking Fields
    created_at = models.DateTimeField(default=timezone.now)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='staging_entries',
        null=True
    )

    # Review Fields
    review_status = models.CharField(
        max_length=20,
        choices=REVIEW_STATUS_CHOICES,
        default='PENDING'
    )
    reviewed_at = models.DateTimeField(null=True, blank=True)
    reviewed_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='reviewed_staging_entries',
        null=True,
        blank=True
    )

    # Optional Additional Fields
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

    class Meta:
        verbose_name_plural = 'Staging Dictionary Entries'
        unique_together = [['word_kh', 'word_en']]
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.word_kh} ({self.word_en})"

class Dictionary(models.Model):
    # Khmer Word Fields
    word_kh = models.CharField(
        max_length=255,
        verbose_name='Khmer Word',
        db_index=True
    )
    word_kh_type = models.CharField(
        max_length=50,
        choices=[
            ('noun', 'Noun'),
            ('verb', 'Verb'),
            ('adjective', 'Adjective'),
            ('adverb', 'Adverb'),
            ('pronoun', 'Pronoun'),
            ('preposition', 'Preposition'),
            ('conjunction', 'Conjunction'),
            ('interjection', 'Interjection')
        ]
    )
    word_kh_definition = models.TextField(
        verbose_name='Khmer Word Definition',
        db_index=True
    )

    # English Word Fields
    word_en = models.CharField(
        max_length=255,
        verbose_name='English Word',
        db_index=True
    )
    word_en_type = models.CharField(
        max_length=50,
        choices=[
            ('noun', 'Noun'),
            ('verb', 'Verb'),
            ('adjective', 'Adjective'),
            ('adverb', 'Adverb'),
            ('pronoun', 'Pronoun'),
            ('preposition', 'Preposition'),
            ('conjunction', 'Conjunction'),
            ('interjection', 'Interjection')
        ]
    )
    word_en_definition = models.TextField(
        verbose_name='English Word Definition',
        db_index=True
    )

    # Example Sentences
    example_sentence_kh = models.TextField(
        null=True,
        blank=True,
        verbose_name='Example Sentence in Khmer',
        db_index=True
    )
    example_sentence_en = models.TextField(
        null=True,
        blank=True,
        verbose_name='Example Sentence in English',
        db_index=True
    )

    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    # Metadata
    created_at = models.DateTimeField(default=timezone.now)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True
    )

    class Meta:
        verbose_name_plural = 'Dictionary Entries'
        indexes = [
            # Multilingual full-text search optimization
            models.Index(fields=['word_kh', 'word_en']),
            models.Index(fields=['word_kh_definition', 'word_en_definition']),
            models.Index(fields=['example_sentence_kh', 'example_sentence_en']),
        ]

    def __str__(self):
        return f"{self.word_kh} ({self.word_en})"

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

    def __str__(self):
        return f"{self.device_id} - {self.word.word_kh}"

