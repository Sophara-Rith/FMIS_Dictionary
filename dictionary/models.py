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
    # Ensure you have an 'id' field (which should be automatic)
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

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['index'],
                name='unique_dictionary_index'
            )
        ]
        indexes = [
            models.Index(fields=['index']),
            models.Index(fields=['word_kh', 'word_en'])
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
        verbose_name_plural = 'Bookmarks'

    def __str__(self):
        return f"Bookmark: {self.word.word_kh} - Device: {self.device_id}"

