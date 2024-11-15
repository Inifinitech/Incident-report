from sqlalchemy_serializer import SerializerMixin
from sqlalchemy import Enum, func, MetaData
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

import requests

metadata = MetaData()
db = SQLAlchemy(metadata=metadata)

# Define Enums for reuse with PostgreSQL compatibility
UserRoleEnum = Enum('admin', 'user', name='user_roles', create_type=True)
ReportStatusEnum = Enum('under investigation', 'resolved', 'rejected', name='report_status', create_type=True)
AdminActionEnum = Enum('status_change', 'flagged', 'resolved', name='admin_actions', create_type=True)

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'
    # serialize_rules = ('-incident_reports', '-admin_acts', '-password',)

    id = db.Column(db.Integer(), primary_key=True)
    username = db.Column(db.String(), nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    phone = db.Column(db.String(), nullable=False)
    password = db.Column(db.String(), nullable=False)
    role = db.Column(UserRoleEnum, default='user')
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())
    banned = db.Column(db.Boolean, default=False)


    incident_reports = db.relationship('Report', back_populates='user', cascade='all, delete')
    admin_acts = db.relationship('Admin', back_populates='admin', cascade='all, delete')
    ratings = db.relationship('Rating', back_populates='user', cascade='all, delete')
    
    serialize_rules = ('-incident_reports', '-admin_acts', '-password','-created_at', )

    @property
    def reports_count(self):
        return len(self.incident_reports)
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'phone': self.phone,
            # 'created_at': self.created_at,
            'reports_count': self.reports_count,
            'banned': self.banned
        }
    
    # def to_dict(self, rules=None):
    #     data = {}
    #     for column in self.__table__.columns:
    #         value = getattr(self, column.name)
    #         # Convert datetime to string if it's a datetime object
    #         if isinstance(value, datetime):
    #             value = value.isoformat()  # or use strftime for a custom format
    #         data[column.name] = value

class Report(db.Model, SerializerMixin):
    __tablename__ = 'incident_reports'

    serialize_rules = ('-user', '-admin_acts', '-images', '-videos',)

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    description = db.Column(db.String(), nullable=False)
    status = db.Column(ReportStatusEnum, default='under investigation')
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    response_time = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, default=func.now())
    updated_at = db.Column(db.DateTime, default=func.now())

    user = db.relationship('User', back_populates='incident_reports', cascade='all, delete')
    admin_acts = db.relationship('Admin', back_populates='incident_report', cascade='all, delete')
    images = db.relationship('ImageUrl', back_populates='report', cascade='all, delete')
    videos = db.relationship('VideoUrl', back_populates='report', cascade='all, delete')
    ratings = db.relationship('Rating', back_populates='report', cascade='all, delete')

    def to_dict(self):
        location = self.reverse_geocode(self.latitude, self.longitude)
        return {
            'id': self.id,
            'description': self.description,
            'status': self.status,
            'location': location,
            'reporter': self.user.username if self.user else None,
            'date': self.created_at.strftime('%Y-%m-%d'), 
            'images': [image.media_image for image in self.images],
            'videos': [video.media_video for video in self.videos]
        }
    
    def reverse_geocode(self, latitude, longitude):
        api_key = 'your_api_key_here'
        url = f'https://api.opencagedata.com/geocode/v1/json?q={latitude}+{longitude}&key={api_key}'
        
        response = requests.get(url)
        data = response.json()

        if data and data['results']:
            return data['results'][0]['formatted']
        else:
            return "Location not available"

class Admin(db.Model, SerializerMixin):
    __tablename__ = 'admin_acts'

    serialize_rules = ('-incident_report', '-emergencies', '-admin',)

    id = db.Column(db.Integer, primary_key=True)
    incident_report_id = db.Column(db.Integer, db.ForeignKey('incident_reports.id'))
    emergency_only_id = db.Column(db.Integer, db.ForeignKey('emergencies.id'))
    action = db.Column(AdminActionEnum)
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=func.now())

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
    status = db.Column(ReportStatusEnum, default='under investigation')
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    phone = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=func.now())
    updated_at = db.Column(db.DateTime, default=func.now())

    admin_acts = db.relationship('Admin', back_populates='emergencies')

    def reverse_geocode(self, latitude, longitude):
        api_key = 'your_api_key_here'
        url = f'https://api.opencagedata.com/geocode/v1/json?q={latitude}+{longitude}&key={api_key}'
        
        response = requests.get(url)
        data = response.json()

        if data and data['results']:
            return data['results'][0]['formatted']
        else:
            return "Location not available"

    def to_dict(self):
        location = self.reverse_geocode(self.latitude, self.longitude)
        return {
            'id': self.id,
            'description': self.description,
            'location': location,
            'status': self.status,
            'reporter': self.name,
            'date': self.created_at.strftime('%Y-%m-%d')
        }

class Notification(db.Model, SerializerMixin):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(), nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=func.now())

class Rating(db.Model, SerializerMixin):
    __tablename__ = 'ratings'
    serialize_rules = ('-report', '-user',)

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    report_id = db.Column(db.Integer, db.ForeignKey('incident_reports.id'), nullable=False)
    rating_value = db.Column(db.Integer, nullable=False)  # Rating value (e.g., 1 to 5 stars)
    created_at = db.Column(db.DateTime, default=func.now())

    user = db.relationship('User', back_populates='ratings', cascade='all, delete')
    report = db.relationship('Report', back_populates='ratings', cascade='all, delete')