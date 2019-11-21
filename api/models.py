import uuid
import sqlalchemy
from django.db import models
from sqlalchemy import text
from sqlalchemy import Column, String, Integer, DateTime, func, Boolean, ForeignKey, ARRAY, Float, BigInteger
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from passlib.hash import pbkdf2_sha256
from api.database.sqlalchemy.connection import Base

class CourseModel(Base):
    __tablename__ = 'courses'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    name = Column(String, unique=True)
    description = Column(String)
    code = Column(String, unique=True)
    mandatory_courses = Column(ARRAY(UUID), default=None)
    mandatory_courses_code = Column(ARRAY(String), default=None)
    credits = Column(Integer)
    created_by = Column(UUID)
    updated_by = Column(UUID)
    approval_score = Column(Float)
    active = Column(Boolean, default=True)
    lessons = relationship("LessonModel", back_populates="course")
    users = relationship("EnrollmentModel", back_populates="course")
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now())

class ChoiceModel(Base):
    __tablename__ = 'choices'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"), index=True)
    question_id = Column(UUID, ForeignKey('questions.id'), index=True)
    question = relationship("QuestionModel", back_populates="choices")
    answer = Column(String)
    is_correct = Column(Boolean)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now())

class EnrollmentModel(Base):
    __tablename__ = "enrollments"

    id = Column(UUID, primary_key=True, server_default=sqlalchemy.text("uuid_generate_v4()"))
    user_id = Column('user_id', UUID, ForeignKey('users.id'))
    user = relationship("UserModel", back_populates="enrollments")
    course_id = Column('course_id', UUID, ForeignKey('courses.id'))
    course = relationship("CourseModel", back_populates="users")
    lesson_scores = relationship("LessonScoreModel", back_populates="enrollment")
    date_of_enrollment = Column(DateTime, default=func.now())
    date_of_completation = Column(DateTime)
    total_score = Column(Float)
    status = Column(String(20))
    active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now())

class LessonModel(Base):
    __tablename__ = 'lessons'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    name = Column(String)
    description = Column(String)
    question_details = Column(String)
    code = Column(String)
    order = Column(Integer, autoincrement=True)
    hours = Column(Integer)
    score = Column(Integer, default=1)
    course_id = Column(UUID, ForeignKey('courses.id'))
    course = relationship("CourseModel", back_populates="lessons")
    created_by = Column(UUID)
    updated_by = Column(UUID)
    questions = relationship("QuestionModel", back_populates="lesson")
    active = Column(Boolean, default=True)
    aproval_score = Column(Integer)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now())

class LessonScoreModel(Base):
    __tablename__ = 'lesson_scores'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    enrollment_id = Column(UUID, ForeignKey('enrollments.id'))
    lesson_id = Column(UUID, ForeignKey('lessons.id'))
    enrollment = relationship("EnrollmentModel", back_populates="lesson_scores")
    lesson_result = Column(Float)
    successful_answers = Column(Integer)
    unsuccessful_answers = Column(Integer)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now())

class QuestionModel(Base):
    __tablename__ = 'questions'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"), index=True)
    question = Column(String)
    code = Column(String)
    score = Column(Integer)
    lesson_id = Column(UUID, ForeignKey('lessons.id'), index=True)
    lesson = relationship("LessonModel", back_populates="questions")
    type_question = Column(String)
    created_by = Column(UUID)
    active = Column(Boolean, default=True)
    answers = Column(ARRAY(String))
    choices = relationship("ChoiceModel", back_populates="question")
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now())

    @classmethod
    def get_correct_answers(cls, lesson_id, session):
        answers_agg = func.array_agg(ChoiceModel.id, type_=ARRAY(UUID)).label('answers')
        return session.query(ChoiceModel.question_id, QuestionModel.score, QuestionModel.type_question, answers_agg). \
                join(QuestionModel.choices) \
                .filter(QuestionModel.lesson_id == lesson_id, ChoiceModel.is_correct) \
                .group_by(ChoiceModel.question_id).group_by(QuestionModel.score) \
                .group_by(QuestionModel.type_question)\
                .all()

class RoleModel(Base):
    __tablename__ = 'roles'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    name = Column(String)
    active = Column(Boolean, default=True)
    user = relationship("UserModel", back_populates="role", uselist=False)
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now())

class TokenModel(Base):
    __tablename__ = 'tokens'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    user_id = Column(UUID, ForeignKey('users.id'))
    access_token = Column(String)
    refresh_token = Column(String)
    access_token_expires_at = Column(BigInteger)
    issued_at = Column(BigInteger)
    refresh_token_expires_in = Column(BigInteger)
    user = relationship("UserModel", back_populates="tokens")
    created_at = Column(DateTime, default=func.now())

class UserModel(Base):
    __tablename__ = 'users'

    id = Column(UUID, primary_key=True, server_default=text("uuid_generate_v4()"))
    name = Column(String)
    lastname = Column(String)
    password = Column(String)
    cellphone = Column(String)
    email = Column(String, unique=True)
    active = Column(Boolean, default=True)
    status = Column(String)
    role_id = Column(UUID, ForeignKey('roles.id'))
    role = relationship("RoleModel", back_populates="user")
    tokens = relationship("TokenModel", back_populates="user")
    enrollments = relationship("EnrollmentModel", back_populates="user")
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now())

    @staticmethod
    def get_hashed_password(plain_text_password):
        # Hash a password for the first time
        #   (Using bcrypt, the salt is saved into the hash itself)
        return pbkdf2_sha256.hash(plain_text_password.encode('utf8'))
        # return bcrypt.hashpw(plain_text_password.encode('utf8'), bcrypt.gensalt())

    @staticmethod
    def check_password(plain_text_password, hashed_password):
        # Check hased password. Useing bcrypt, the salt is saved into the hash itself
        return pbkdf2_sha256.verify(plain_text_password.encode('utf8'), hashed_password)
        # return bcrypt.checkpw(plain_text_password.encode('utf8'), hashed_password)


