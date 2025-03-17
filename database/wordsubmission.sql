-- MySQL dump 10.13  Distrib 8.0.41, for Win64 (x86_64)
--
-- Host: 127.0.0.1    Database: dictionary
-- ------------------------------------------------------
-- Server version	8.0.41

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `wordsubmission`
--

DROP TABLE IF EXISTS `wordsubmission`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `wordsubmission` (
  `submit_id` int NOT NULL AUTO_INCREMENT,
  `dictionary_id` int DEFAULT NULL,
  `submitted_by_id` int DEFAULT NULL,
  `reviewed_by_id` int DEFAULT NULL,
  `word_kh` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `word_en` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `pronunciation` varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `definition_kh` text COLLATE utf8mb4_unicode_ci,
  `definition_en` text COLLATE utf8mb4_unicode_ci,
  `word_type` enum('NOUN','VERB','ADJECTIVE','ADVERB','PRONOUN','PREPOSITION','CONJUNCTION','INTERJECTION') COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  `status` enum('PENDING','APPROVED','REJECTED') COLLATE utf8mb4_unicode_ci DEFAULT 'PENDING',
  `submitted_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP,
  `reviewed_at` timestamp NULL DEFAULT NULL,
  PRIMARY KEY (`submit_id`),
  KEY `dictionary_id` (`dictionary_id`),
  KEY `idx_status` (`status`),
  KEY `idx_submitted_by` (`submitted_by_id`),
  KEY `idx_reviewed_by` (`reviewed_by_id`),
  CONSTRAINT `wordsubmission_ibfk_1` FOREIGN KEY (`dictionary_id`) REFERENCES `dictionary` (`dictionary_id`) ON DELETE SET NULL,
  CONSTRAINT `wordsubmission_ibfk_2` FOREIGN KEY (`submitted_by_id`) REFERENCES `user` (`user_id`) ON DELETE CASCADE,
  CONSTRAINT `wordsubmission_ibfk_3` FOREIGN KEY (`reviewed_by_id`) REFERENCES `user` (`user_id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `wordsubmission`
--

LOCK TABLES `wordsubmission` WRITE;
/*!40000 ALTER TABLE `wordsubmission` DISABLE KEYS */;
/*!40000 ALTER TABLE `wordsubmission` ENABLE KEYS */;
UNLOCK TABLES;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2025-03-17  9:24:27
