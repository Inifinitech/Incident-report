# from flask_sqlalchemy import SQLAlchemy
# from sqlalchemy_serializer import SerializerMixin
# from sqlalchemy import Enum, func, DateTime

# db = SQLAlchemy()

# class User(db.Model, SerializerMixin):
#     __tablename__ = 'users'

#     id = db.Column(db.Integer, primary_key=True)
#     username = db.Column(db.String, nullable=False)
#     email = db.Column(db.String, unique=True, nullable=False)
#     password = db.Column(db.String, nullable=False)
#     role = db.Column(Enum('admin', 'user'), default='user')
#     created_at = db.Column(db.DateTime, default=func.now())

#     # Adjust relationship to match 'incident_reports' table in the Report model
#     incident_reports = db.relationship('Report', back_populates='user', cascade='all, delete')
#     # Added relationship for Admin actions
#     admin_acts = db.relationship('Admin', back_populates='admin', cascade='all, delete')
#     # notifications = db.relationship('Notification', back_populates='user', cascade='all, delete')


# class Report(db.Model, SerializerMixin):
#     __tablename__ = 'incident_reports'

#     id = db.Column(db.Integer, primary_key=True)
#     user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     title = db.Column(db.String, nullable=False)
#     description = db.Column(db.String, nullable=False)
#     status = db.Column(Enum('under investigation', 'resolved', 'rejected'), default='under investigation')
#     latitude = db.Column(db.Float, nullable=False)
#     longitude = db.Column(db.Float, nullable=False)
#     created_at = db.Column(db.DateTime, default=func.now())
#     updated_at = db.Column(db.DateTime, default=func.now())

#     # Relationship to the User
#     user = db.relationship('User', back_populates='incident_reports', cascade='all, delete')
#     # Relationship to Admin actions
#     admin_acts = db.relationship('Admin', back_populates='incident_report', cascade='all, delete')
#     # Relationship to Media
#     medias = db.relationship('Media', back_populates='report', cascade='all, delete')


# class Admin(db.Model, SerializerMixin):
#     __tablename__ = 'admins_acts'

#     id = db.Column(db.Integer, primary_key=True)
#     incident_report_id = db.Column(db.Integer, db.ForeignKey('incident_reports.id'))
#     action = db.Column(Enum('status_change', 'flagged', 'resolved'))
#     admin_id = db.Column(db.Integer, db.ForeignKey('users.id'))
#     create_at = db.Column(db.DateTime, default=func.now())

#     # Relationship to Report
#     incident_report = db.relationship('Report', back_populates='admin_acts', cascade='all, delete')
#     # Relationship to User (Admin should reference User)
#     admin = db.relationship('User', back_populates='admin_acts', cascade='all, delete')


# class Media(db.Model, SerializerMixin):
#     __tablename__ = 'incident_medias'

#     id = db.Column(db.Integer, primary_key=True)
#     incident_report_id = db.Column(db.Integer, db.ForeignKey('incident_reports.id'), nullable=False)
#     media_type = db.Column(Enum('image', 'video'), nullable=False)
#     media_url = db.Column(db.String, nullable=False)

#     # Relationship to Report
#     report = db.relationship('Report', back_populates='medias', cascade='all, delete')


# class Notification(db.Model, SerializerMixin):
#     __tablename__ = 'notifications'

#     id = db.Column(db.Integer, primary_key=True)
#     # user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
#     message = db.Column(db.String, nullable=False)
#     read = db.Column(db.Boolean)
#     created_at = db.Column(db.DateTime, default=func.now())

#     # # Relationship to User
#     # user = db.relationship('User', back_populates='notifications', cascade='all, delete')

# class Rating(db.Model):
#     id = db.Column(db.Integer, primary_key=True)
#     rating = db.Column(db.Integer, nullable=False)
#     feedback = db.Column(db.String(500), nullable=True)
#     incident_id = db.Column(db.Integer, db.ForeignKey('incident.id'), nullable=False)

#     incident = db.relationship('Incident', backref='ratings')

#     def __repr__(self):
#         return f'<Rating {self.rating}, Feedback {self.feedback}>'

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy_serializer import SerializerMixin
from sqlalchemy import Enum, func, DateTime

db = SQLAlchemy()

class User(db.Model, SerializerMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    email = db.Column(db.String, unique=True, nullable=False)
    password = db.Column(db.String, nullable=False)
    role = db.Column(Enum('admin', 'user'), default='user')
    created_at = db.Column(db.DateTime, default=func.now())

    # Relationships
    incident_reports = db.relationship('Report', back_populates='user', cascade='all, delete')
    admin_acts = db.relationship('Admin', back_populates='admin', cascade='all, delete')
    notifications = db.relationship('Notification', back_populates='user', cascade='all, delete')

    def __repr__(self):
        return f"<User id={self.id}, username={self.username}, email={self.email}, role={self.role}>"

class Report(db.Model, SerializerMixin):
    __tablename__ = 'incident_reports'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    title = db.Column(db.String, nullable=False)
    description = db.Column(db.String, nullable=False)
    status = db.Column(Enum('under investigation', 'resolved', 'rejected'), default='under investigation')
    latitude = db.Column(db.Float, nullable=False)
    longitude = db.Column(db.Float, nullable=False)
    created_at = db.Column(db.DateTime, default=func.now())
    updated_at = db.Column(db.DateTime, default=func.now(), onupdate=func.now())

    # Relationships
    user = db.relationship('User', back_populates='incident_reports')
    admin_acts = db.relationship('Admin', back_populates='incident_report', cascade='all, delete')
    medias = db.relationship('Media', back_populates='report', cascade='all, delete')
    ratings = db.relationship('Rating', back_populates='report', cascade='all, delete')

    def __repr__(self):
        return f"<Report id={self.id}, title={self.title}, status={self.status}, user_id={self.user_id}>"

class Admin(db.Model, SerializerMixin):
    __tablename__ = 'admin_acts'

    id = db.Column(db.Integer, primary_key=True)
    incident_report_id = db.Column(db.Integer, db.ForeignKey('incident_reports.id'))
    action = db.Column(Enum('status_change', 'flagged', 'resolved'))
    admin_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=func.now())

    # Relationships
    incident_report = db.relationship('Report', back_populates='admin_acts')
    admin = db.relationship('User', back_populates='admin_acts')

    def __repr__(self):
        return f"<Admin id={self.id}, action={self.action}, admin_id={self.admin_id}, report_id={self.incident_report_id}>"

class Media(db.Model, SerializerMixin):
    __tablename__ = 'incident_medias'

    id = db.Column(db.Integer, primary_key=True)
    incident_report_id = db.Column(db.Integer, db.ForeignKey('incident_reports.id'), nullable=False)
    media_type = db.Column(Enum('image', 'video'), nullable=False)
    media_url = db.Column(db.String, nullable=False)

    # Relationship
    report = db.relationship('Report', back_populates='medias')

    def __repr__(self):
        return f"<Media id={self.id}, media_type={self.media_type}, report_id={self.incident_report_id}>"

class Notification(db.Model, SerializerMixin):
    __tablename__ = 'notifications'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    message = db.Column(db.String, nullable=False)
    read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=func.now())

    # Relationship
    user = db.relationship('User', back_populates='notifications')

    def __repr__(self):
        return f"<Notification id={self.id}, user_id={self.user_id}, read={self.read}>"

class Rating(db.Model, SerializerMixin):
    __tablename__ = 'ratings'

    id = db.Column(db.Integer, primary_key=True)
    rating = db.Column(db.Integer, nullable=False)
    feedback = db.Column(db.String(500), nullable=True)
    report_id = db.Column(db.Integer, db.ForeignKey('incident_reports.id'), nullable=False)

    # Relationship
    report = db.relationship('Report', back_populates='ratings')

    def __repr__(self):
        return f"<Rating id={self.id}, rating={self.rating}, feedback={self.feedback}, report_id={self.report_id}>"
