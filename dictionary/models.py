# dictionary/models.py
from django.db import models
from django.utils import timezone
from users.models import User

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

class Dictionary(models.Model):
    word_kh = models.CharField(max_length=255)
    word_en = models.CharField(max_length=255)
    definition_kh = models.TextField()
    definition_en = models.TextField()
    word_type_en = models.CharField(
        max_length=20,
        choices=WordType.WORD_TYPE_CHOICES_EN
    )
    word_type_kh = models.CharField(
        max_length=50,
        choices=WordType.WORD_TYPE_CHOICES_KH
    )

    # Relationship fields
    created_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        related_name='created_words',
        null=True
    )
    updated_by = models.ForeignKey(
        User,
        on_delete=models.SET_NULL,
        related_name='updated_words',
        null=True
    )

    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.word_en} ({self.word_kh})"

    class Meta:
        verbose_name_plural = "Dictionary Words"
        ordering = ['-created_at']
