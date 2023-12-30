-- mySQL Query to create database fit_lohas
CREATE DATABASE IF NOT EXISTS `fit_lohas`;

-- mySQL Query to create table users
CREATE TABLE users (
    UserID INT AUTO_INCREMENT PRIMARY KEY,
    Username VARCHAR(50) NOT NULL,
    Email VARCHAR(100) UNIQUE NOT NULL,
    PasswordHash VARCHAR(200) NOT NULL,
    AvatarPath VARCHAR(200) DEFAULT '/assets/images/avatars/000-default.png ',
    FullName VARCHAR(100),
    UserRole VARCHAR(50) DEFAULT 'STUDENT',
    PhoneNumber VARCHAR(20),
    Address VARCHAR(200),
    Gender ENUM('Male', 'Female', 'Other'),
    CreatedDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ModifyDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- mySQL Query to insert data into table users
INSERT INTO users (
    UserID,
    Username, 
    Email, 
    PasswordHash, 
    AvatarPath, 
    FullName, 
    UserRole, 
    Address, 
    Gender
) VALUES (
    1,
    'admin', 
    'admin@gmail.com', 
    '9e37a8d2e30bb3c7a36f2e1646c0154c835f56175307445146b9bb0f80fdb1d6',  -- Password: dummyPass
    '/assets/images/face-0.png', 
    'Super user', 
    'ADMIN', 
    'Taiwan NCHU', 
    'Male'
);

INSERT INTO users(
    UserID,
    Username,
    Email,
    PasswordHash,
    UserRole
) VALUES (
    2,
    'teacher01', 
    'teacher01@gmail.com',
    '9e37a8d2e30bb3c7a36f2e1646c0154c835f56175307445146b9bb0f80fdb1d6',  -- Password: dummyPass
    'TEACHER'
),
( 
    3,
    'teacher02', 
    'teacher02@gmail.com',
    '9e37a8d2e30bb3c7a36f2e1646c0154c835f56175307445146b9bb0f80fdb1d6',  -- Password: dummyPass
    'TEACHER'
);

INSERT INTO users(
    UserID,
    Username,
    Email,
    PasswordHash
) VALUES ( 
    4,
    'student01', 
    'student01@gmail.com',
    '9e37a8d2e30bb3c7a36f2e1646c0154c835f56175307445146b9bb0f80fdb1d6'  -- Password: dummyPass
),
(
    5,
    'student02', 
    'student02@gmail.com',
    '9e37a8d2e30bb3c7a36f2e1646c0154c835f56175307445146b9bb0f80fdb1d6'  -- Password: dummyPass
);

-- mySQL Query to create table teachers with two attributes: TeacherID and Salary, where TeacherID is a foreign key referencing to UserID in table users
CREATE TABLE teachers (
    TeacherID INT AUTO_INCREMENT PRIMARY KEY,
    UserID INT,
    Salary DECIMAL(10, 2),
    CreatedDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ModifyDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (UserID) REFERENCES users(UserID)
);

-- mySQL Query to insert data into table teachers
INSERT INTO teachers (
    UserID, 
    Salary
) VALUES (
    2, 
    100000
),
(
    3, 
    200000
);

-- mySQL Query to create table courses  with four attributes: CourseID, TeacherID, CreatedDate, ModifyDate
CREATE TABLE courses  (
    CourseID INT AUTO_INCREMENT PRIMARY KEY,
    CourseName VARCHAR(100) NOT NULL,
    CourseDescription VARCHAR(200) NOT NULL,
    Category VARCHAR(50),
    TeacherID INT,
    CreatedDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ModifyDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (TeacherID) REFERENCES teachers(TeacherID)
);

-- Inserting course 1: Cardio Kickboxing
INSERT INTO courses (CourseName, CourseDescription, Category, TeacherID)
VALUES (
    'Cardio Kickboxing',
    'High-energy workout combining martial arts techniques and heart-pumping cardio.',
    'Kickboxing',
    1
),
(
    'Strength Training 101',
    'Introduction to basic strength exercises focusing on building muscle and strength.',
    'Strength Training',
    2
),
(
    'Yoga for Flexibility',
    'Gentle yoga practice aimed at improving flexibility and reducing stress.',
    'Yoga',
    2
),
(
    'Advanced Kickboxing Techniques',
    'Advanced techniques and combinations for experienced practitioners.',
    'Kickboxing',
    1
),
(
    'Powerlifting Essentials',
    'Focus on powerlifting exercises for building maximum strength.',
    'Strength Training',
    2
),
(
    'Mindful Meditation through Yoga',
    'Learn mindfulness and meditation practices through yoga poses.',
    'Yoga',
    2
);

-- CourseEnter (CourseID, UserID, CreatedDate, ModifyDate)
CREATE TABLE CourseEnter (
    CourseID INT,
    UserID INT,
    CreatedDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ModifyDate TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    FOREIGN KEY (CourseID) REFERENCES courses(CourseID),
    FOREIGN KEY (UserID) REFERENCES users(UserID),
    PRIMARY KEY (CourseID, UserID)
);

-- Inserting CourseEnter 1: Cardio Kickboxing
INSERT INTO CourseEnter (CourseID, UserID)
VALUES (1, 4), (2, 4), (3, 5);

