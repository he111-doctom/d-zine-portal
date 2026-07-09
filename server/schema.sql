-- ================================================
-- D'zine Brand Studio — Database Schema
-- Run this ONCE to set up the database.
-- ================================================

CREATE DATABASE IF NOT EXISTS dzine_portal CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE dzine_portal;

-- Users table
CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    full_name     VARCHAR(255) NOT NULL,
    company_name  VARCHAR(255) DEFAULT '',
    role          ENUM('client','admin','studio') DEFAULT 'client',
    is_active     TINYINT(1) DEFAULT 1,
    last_login    DATETIME NULL,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- Projects table
CREATE TABLE IF NOT EXISTS projects (
    id                  INT AUTO_INCREMENT PRIMARY KEY,
    client_id           INT NOT NULL,
    project_name        VARCHAR(255) NOT NULL,
    project_description TEXT,
    status              ENUM('pending','active','completed','archived') DEFAULT 'active',
    current_stage       VARCHAR(50) DEFAULT 'questionnaire',
    progress_percentage INT DEFAULT 0,
    start_date          DATETIME NULL,
    completion_date     DATETIME NULL,
    created_at          DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Project stages
CREATE TABLE IF NOT EXISTS project_stages (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    project_id  INT NOT NULL,
    stage_key   VARCHAR(50) NOT NULL,
    stage_name  VARCHAR(100) NOT NULL,
    status      ENUM('locked','pending','in_review','approved') DEFAULT 'locked',
    order_index INT DEFAULT 0,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_project_stage (project_id, stage_key),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Questionnaires
CREATE TABLE IF NOT EXISTS questionnaires (
    id             INT AUTO_INCREMENT PRIMARY KEY,
    project_id     INT NOT NULL,
    question_index INT NOT NULL,
    answer_value   TEXT,
    is_submitted   TINYINT(1) DEFAULT 0,
    created_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at     DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_q_proj_idx (project_id, question_index),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Color selections
CREATE TABLE IF NOT EXISTS color_selections (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    project_id      INT NOT NULL UNIQUE,
    primary_color   VARCHAR(20),
    secondary_color VARCHAR(20),
    accent_color    VARCHAR(20),
    neutral_color   VARCHAR(20),
    is_approved     TINYINT(1) DEFAULT 0,
    created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at      DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Logo designs
CREATE TABLE IF NOT EXISTS logo_designs (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    project_id    INT NOT NULL,
    concept_index INT NOT NULL,
    image_url     VARCHAR(500),
    feedback      TEXT,
    is_approved   TINYINT(1) DEFAULT 0,
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uq_logo_concept (project_id, concept_index),
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- File uploads
CREATE TABLE IF NOT EXISTS uploads (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    project_id  INT NOT NULL,
    upload_key  VARCHAR(100) NOT NULL,
    file_name   VARCHAR(255) NOT NULL,
    file_path   VARCHAR(500) NOT NULL,
    file_type   VARCHAR(100),
    file_size   INT DEFAULT 0,
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB;


-- Feedback from clients on design stages
CREATE TABLE IF NOT EXISTS feedback (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    project_id    INT NOT NULL,
    section_key   VARCHAR(50) NOT NULL,
    feedback_text TEXT NOT NULL,
    user_name     VARCHAR(100) DEFAULT 'Client',
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at    DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- ================================================
-- DEFAULT ADMIN USER
-- Email: admin@dzine.com / Password: admin123
-- !! CHANGE THE PASSWORD AFTER FIRST LOGIN !!
-- ================================================
INSERT IGNORE INTO users (email, password_hash, full_name, role)
VALUES (
    'admin@dzine.com',
    '$2a$12$kamLJxsEZ/zC1YQjYlAdHObXZ5ZYAsgY9K0zzYTXhDn/cSLpvttWS',
    'D''zine Admin',
    'admin'
);
