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

class StagingDictionaryEntry(models.Model):
    REVIEW_STATUS_CHOICES = [
        ('PENDING', 'Pending Review'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected')
    ]

    # Khmer Word Fields
    word_kh = models.CharField(
        max_length=255,
        verbose_name='Khmer Word',
        validators=[MinLengthValidator(1, "Khmer word cannot be empty")]
    )
    word_kh_type = models.CharField(
        max_length=50,
        choices=WordType.WORD_TYPE_CHOICES_KH,
        verbose_name='Khmer Word Type'
    )
    word_kh_definition = models.TextField(
        verbose_name='Khmer Word Definition',
        validators=[MinLengthValidator(5, "Definition must be at least 5 characters")]
    )

    # English Word Fields
    word_en = models.CharField(
        max_length=255,
        verbose_name='English Word',
        validators=[MinLengthValidator(1, "English word cannot be empty")]
    )
    word_en_type = models.CharField(
        max_length=20,
        choices=WordType.WORD_TYPE_CHOICES_EN,
        verbose_name='English Word Type'
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

    # Metadata Fields
    rejection_reason = models.TextField(
        null=True,
        blank=True,
        verbose_name='Reason for Rejection'
    )
    source = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        verbose_name='Source of Entry'
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
        null=True,
        blank=True,
        verbose_name='Example Sentence in Khmer'
    )
    example_sentence_en = models.TextField(
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

    def clean(self):
        # Additional validation can be added here
        from django.core.exceptions import ValidationError

        # Ensure word types match
        type_map = dict(zip(
            [t[0] for t in WordType.WORD_TYPE_CHOICES_EN],
            [t[0] for t in WordType.WORD_TYPE_CHOICES_KH]
        ))

        if self.word_en_type and self.word_kh_type:
            if type_map.get(self.word_en_type) != self.word_kh_type:
                raise ValidationError({
                    'word_type': 'English and Khmer word types must match'
                })

class DictionaryEntry(models.Model):
    # Khmer Word Fields
    word_kh = models.CharField(
        max_length=255,
        verbose_name='Khmer Word',
        validators=[MinLengthValidator(1, "Khmer word cannot be empty")]
    )
    word_kh_type = models.CharField(
        max_length=50,
        choices=WordType.WORD_TYPE_CHOICES_KH,
        verbose_name='Khmer Word Type'
    )
    word_kh_definition = models.TextField(
        verbose_name='Khmer Word Definition',
        validators=[MinLengthValidator(5, "Definition must be at least 5 characters")]
    )

    # English Word Fields
    word_en = models.CharField(
        max_length=255,
        verbose_name='English Word',
        validators=[MinLengthValidator(1, "English word cannot be empty")]
    )
    word_en_type = models.CharField(
        max_length=20,
        choices=WordType.WORD_TYPE_CHOICES_EN,
        verbose_name='English Word Type'
    )
    word_en_definition = models.TextField(
        verbose_name='English Word Definition',
        validators=[MinLengthValidator(5, "Definition must be at least 5 characters")]
    )

    # Metadata Fields
    index = models.IntegerField(
        unique=True,
        verbose_name='Dictionary Index'
    )

    # Tracking Fields
    created_at = models.DateTimeField(default=timezone.now)
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        related_name='created_entries',
        null=True
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
        null=True,
        blank=True,
        verbose_name='Example Sentence in Khmer'
    )
    example_sentence_en = models.TextField(
        null=True,
        blank=True,
        verbose_name='Example Sentence in English'
    )

    # Additional Metadata
    source = models.CharField(
        max_length=100,
        null=True,
        blank=True,
        verbose_name='Source of Entry'
    )
    is_verified = models.BooleanField(
        default=False,
        verbose_name='Verified Entry'
    )
    difficulty_level = models.CharField(
        max_length=20,
        choices=[
            ('BEGINNER', 'Beginner'),
            ('INTERMEDIATE', 'Intermediate'),
            ('ADVANCED', 'Advanced')
        ],
        null=True,
        blank=True
    )

    class Meta:
        verbose_name_plural = 'Dictionary Entries'
        ordering = ['index']
        unique_together = [['word_kh', 'word_en']]

    def __str__(self):
        return f"{self.word_kh} ({self.word_en})"

    def save(self, *args, **kwargs):
        # Auto-generate index if not provided
        if not self.index:
            last_entry = DictionaryEntry.objects.order_by('-index').first()
            self.index = (last_entry.index + 1) if last_entry else 1

        super().save(*args, **kwargs)

class Bookmark(models.Model):
    device_id = models.CharField(max_length=255)
    word = models.ForeignKey(
        'DictionaryEntry',
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

