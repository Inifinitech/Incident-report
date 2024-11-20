from sqlalchemy_serializer import SerializerMixin
from sqlalchemy import func, MetaData
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from enum import Enum

import requests

metadata = MetaData()
db = SQLAlchemy(metadata=metadata)

# Define Enums for reuse with PostgreSQL compatibility
# UserRoleEnum = Enum('admin', 'user', name='user_roles', create_type=True)
# ReportStatusEnum = Enum('under investigation', 'resolved', 'rejected', name='report_status', create_type=True)
# AdminActionEnum = Enum('status_change', 'flagged', 'resolved', name='admin_actions', create_type=True)

class UserRoleEnum(Enum):
    user = 'user'
    admin = 'admin'

class ReportStatusEnum(Enum):
    under_investigation = 'under investigation'
    resolved = 'resolved'
    rejected = 'rejected'

class AdminActionEnum(Enum):
    status_change = 'status change'
    flagged = 'flagged'
    resolved = 'resolved'

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    phone = db.Column(db.String(), nullable=False)
    password = db.Column(db.String(), nullable=False)
    role = db.Column(db.String())
    created_at = db.Column(db.DateTime)
    banned = db.Column(db.Boolean, default=False)


    incident_reports = db.relationship('Report', back_populates='user', cascade='all, delete')
    admin_acts = db.relationship('Admin', back_populates='admin', cascade='all, delete')
    ratings = db.relationship('Rating', back_populates='user', cascade='all, delete')
    
    serialize_rules = ('-incident_reports.id', '-admin_acts', '-password', )

    @property
    def reports_count(self):
        return len(self.incident_reports)
    
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'phone': self.phone,
            'created_at': self.created_at,
            'reports_count': self.reports_count,
            'banned': self.banned, 
            'role': self.role,
            'incident_reports': [incident.to_dict() for incident in self.incident_reports]  # Calling to_dict() on each incident
        }
    

class Report(db.Model, SerializerMixin):
    __tablename__ = 'incident_reports'

    serialize_rules = ('-user', '-admin_acts',)

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    description = db.Column(db.String(), nullable=False)
    status = db.Column(db.String(), default='under investigation')
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    response_time = db.Column(db.Integer)
    created_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime)

    user = db.relationship('User', back_populates='incident_reports', cascade='all, delete')
    admin_acts = db.relationship('Admin', back_populates='incident_report', cascade='all, delete')
    images = db.relationship('ImageUrl', back_populates='report', cascade='all, delete')
    videos = db.relationship('VideoUrl', back_populates='report', cascade='all, delete')
    ratings = db.relationship('Rating', back_populates='report', cascade='all, delete')


    def to_dict(self):
        return {
            'id': self.id,
            'description': self.description,
            'status': self.status,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'reporter': self.user.username if self.user else None,
            'date': self.created_at, 
            'images': [image.media_image for image in self.images],
            'videos': [video.media_video for video in self.videos]
        }


class Admin(db.Model, SerializerMixin):
    __tablename__ = 'admin_acts'

    serialize_rules = ('-incident_report', '-emergencies', '-admin',)

    id = db.Column(db.Integer, primary_key=True)
    incident_report_id = db.Column(db.Integer, db.ForeignKey('incident_reports.id'))
    emergency_only_id = db.Column(db.Integer, db.ForeignKey('emergencies.id'))
    action = db.Column(db.String())
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime)

    incident_report = db.relationship('Report', back_populates='admin_acts', cascade='all, delete')
    emergencies = db.relationship('EmergencyReport', back_populates='admin_acts')
    admin = db.relationship('User', back_populates='admin_acts', cascade='all, delete')

class ImageUrl(db.Model, SerializerMixin):
    __tablename__ = 'images'

    serialize_rules = ('-report',)

    id = db.Column(db.Integer, primary_key=True)
    incident_report_id = db.Column(db.Integer, db.ForeignKey('incident_reports.id'))
    media_image = db.Column(db.String())

    report = db.relationship('Report', back_populates='images', cascade='all, delete')

class VideoUrl(db.Model, SerializerMixin):
    __tablename__ = 'videos'

    serialize_rules = ('-report',)

    id = db.Column(db.Integer, primary_key=True)
    incident_report_id = db.Column(db.Integer, db.ForeignKey('incident_reports.id'))
    media_video = db.Column(db.String())

    report = db.relationship('Report', back_populates='videos', cascade='all, delete')

class EmergencyReport(db.Model, SerializerMixin):
    __tablename__ = 'emergencies'

    serialize_rules = ('-admin_acts',)

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(), nullable=False)
    description = db.Column(db.String(), nullable=False)
    status = db.Column(db.String(), default='under investigation')
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    phone = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime)

    admin_acts = db.relationship('Admin', back_populates='emergencies')

    def to_dict(self):
        return {
        'id': self.id,
        'description': self.description,
        'status': self.status,
        'latitude': self.latitude,
        'longitude': self.longitude,
        'reporter': self.name if self.name else None,
        'date': self.created_at
        }

class Notification(db.Model, SerializerMixin):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(), nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime)

class Rating(db.Model, SerializerMixin):
    __tablename__ = 'ratings'
    serialize_rules = ('-report', '-user',)

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('incident_reports.id'), nullable=False)
    rating_value = db.Column(db.Integer, nullable=False)
    feedback = db.Column(db.String(), nullable=False) 
    created_at = db.Column(db.DateTime)

    user = db.relationship('User', back_populates='ratings', cascade='all, delete')
    report = db.relationship('Report', back_populates='ratings', cascade='all, delete')

class ContactMessage(db.Model):
    __tablename__='contact_messages'
    
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())