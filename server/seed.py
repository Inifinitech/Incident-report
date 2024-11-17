from models import db, User, Report, Admin,ImageUrl,EmergencyReport,VideoUrl, Notification, Rating
from app import app
# users = [
#     {"username": "john_doe", "email": "john.doe@example.com", "phone": "1234567890", "password": "password123", "role": 'user'},
#     {"username": "jane_doe", "email": "jane.doe@example.com", "phone": "9876543210", "password": "password456", "role": 'admin'},
#     {"username": "alex_smith", "email": "alex.smith@example.com", "phone": "1112223333", "password": "password789", "role": 'user'},
#     {"username": "linda_brown", "email": "linda.brown@example.com", "phone": "4445556666", "password": "password321", "role": 'user'},
#     {"username": "mark_jones", "email": "mark.jones@example.com", "phone": "7778889999", "password": "password654", "role": 'admin'},
#     {"username": "susan_clark", "email": "susan.clark@example.com", "phone": "2223334444", "password": "password987", "role": 'user'},
#     {"username": "mike_taylor", "email": "mike.taylor@example.com", "phone": "5556667777", "password": "password111", "role": 'user'},
#     {"username": "emma_wilson", "email": "emma.wilson@example.com", "phone": "9990001111", "password": "password222", "role": 'user'},
#     {"username": "paul_miller", "email": "paul.miller@example.com", "phone": "8887776666", "password": "password333", "role": 'admin'}
# ]

# with app.app_context():
#     db.session.add_all([User(**user) for user in users])
#     db.session.commit()

# reports = [
#     {"user_id": 1, "description": "Power outage in city block A", "status": 'under investigation', "latitude": 40.7128, "longitude": -74.0060},
#     {"user_id": 2, "description": "Water leak in apartment complex", "status": 'resolved', "latitude": 34.0522, "longitude": -118.2437},
#     {"user_id": 3, "description": "Streetlight malfunction", "status": 'under investigation', "latitude": 41.8781, "longitude": -87.6298},
#     {"user_id": 4, "description": "Pothole on main road", "status": 'rejected', "latitude": 29.7604, "longitude": -95.3698},
#     {"user_id": 5, "description": "Broken traffic signal", "status": 'resolved', "latitude": 39.7392, "longitude": -104.9903},
#     {"user_id": 6, "description": "Large-scale flood warning", "status": 'under investigation', "latitude": 25.7617, "longitude": -80.1918},
#     {"user_id": 7, "description": "Tree fallen on street", "status": 'resolved', "latitude": 32.7767, "longitude": -96.7970},
#     {"user_id": 8, "description": "Fire alarm in neighborhood", "status": 'under investigation', "latitude": 47.6062, "longitude": -122.3321},
#     {"user_id": 9, "description": "Severe storm damage", "status": 'rejected', "latitude": 37.7749, "longitude": -122.4194}
# ]

# with app.app_context():
#     db.session.add_all([Report(**report) for report in reports])
#     db.session.commit()

# admin_actions = [
#     {"incident_report_id": 1, "action": 'status_change', "admin_id": 2},
#     {"incident_report_id": 2, "action": 'flagged', "admin_id": 5},
#     {"incident_report_id": 3, "action": 'resolved', "admin_id": 9},
#     {"incident_report_id": 4, "action": 'status_change', "admin_id": 2},
#     {"incident_report_id": 5, "action": 'flagged', "admin_id": 5},
#     {"incident_report_id": 6, "action": 'resolved', "admin_id": 9},
#     {"incident_report_id": 7, "action": 'status_change', "admin_id": 2},
#     {"incident_report_id": 8, "action": 'flagged', "admin_id": 5},
#     {"incident_report_id": 9, "action": 'resolved', "admin_id": 9}
# ]

# with app.app_context():
#     db.session.add_all([Admin(**action) for action in admin_actions])
#     db.session.commit()

# image_urls = [
#     {"incident_report_id": 1, "media_image": "image1.jpg"},
#     {"incident_report_id": 2, "media_image": "image2.jpg"},
#     {"incident_report_id": 3, "media_image": "image3.jpg"},
#     {"incident_report_id": 4, "media_image": "image4.jpg"},
#     {"incident_report_id": 5, "media_image": "image5.jpg"},
#     {"incident_report_id": 6, "media_image": "image6.jpg"},
#     {"incident_report_id": 7, "media_image": "image7.jpg"},
#     {"incident_report_id": 8, "media_image": "image8.jpg"},
#     {"incident_report_id": 9, "media_image": "image9.jpg"}
# ]

# with app.app_context():
#     db.session.add_all([ImageUrl(**image) for image in image_urls])
#     db.session.commit()

# video_urls = [
#     {"incident_report_id": 1, "media_video": "video1.mp4"},
#     {"incident_report_id": 2, "media_video": "video2.mp4"},
#     {"incident_report_id": 3, "media_video": "video3.mp4"},
#     {"incident_report_id": 4, "media_video": "video4.mp4"},
#     {"incident_report_id": 5, "media_video": "video5.mp4"},
#     {"incident_report_id": 6, "media_video": "video6.mp4"},
#     {"incident_report_id": 7, "media_video": "video7.mp4"},
#     {"incident_report_id": 8, "media_video": "video8.mp4"},
#     {"incident_report_id": 9, "media_video": "video9.mp4"}
# ]

# with app.app_context():
#     db.session.add_all([VideoUrl(**video) for video in video_urls])
#     db.session.commit()

# emergency_reports = [
#     {"name": "Flood Alert", "description": "Flood reported in city sector C", "status": 'under investigation', "latitude": 40.7128, "longitude": -74.0060, "phone": 1234567890},
#     {"name": "Fire Breakout", "description": "Fire detected in downtown warehouse", "status": 'resolved', "latitude": 34.0522, "longitude": -118.2437, "phone": 9876543210},
#     {"name": "Tornado Warning", "description": "Tornado forecast in the northern region", "status": 'under investigation', "latitude": 41.8781, "longitude": -87.6298, "phone": 1112223333},
#     {"name": "Gas Leak", "description": "Gas leak reported in residential area", "status": 'rejected', "latitude": 29.7604, "longitude": -95.3698, "phone": 4445556666},
#     {"name": "Earthquake Aftershock", "description": "Mild aftershocks expected", "status": 'resolved', "latitude": 39.7392, "longitude": -104.9903, "phone": 7778889999},
#     {"name": "Severe Thunderstorm", "description": "Thunderstorm in sector B", "status": 'under investigation', "latitude": 25.7617, "longitude": -80.1918, "phone": 2223334444},
#     {"name": "Wildfire", "description": "Wildfire reported in forest region", "status": 'resolved', "latitude": 32.7767, "longitude": -96.7970, "phone": 5556667777},
#     {"name": "Blizzard Warning", "description": "Heavy snowfall expected", "status": 'under investigation', "latitude": 47.6062, "longitude": -122.3321, "phone": 9990001111},
#     {"name": "Power Outage", "description": "Citywide power outage", "status": 'rejected', "latitude": 37.7749, "longitude": -122.4194, "phone": 8887776666}
# ]

# with app.app_context():
#     db.session.add_all([EmergencyReport(**emergency) for emergency in emergency_reports])
#     db.session.commit()

# notifications = [
#     {"message": "New report has been filed.", "read": False},
#     {"message": "Your report status has been updated.", "read": False},
#     {"message": "A new admin action has been taken on your report.", "read": True},
#     {"message": "You have received a new rating.", "read": False},
#     {"message": "Your incident report is resolved.", "read": True},
#     {"message": "There was a new update on your emergency report.", "read": False},
#     {"message": "Admin has reviewed your report.", "read": True},
#     {"message": "Your report has been rejected.", "read": True},
#     {"message": "You have been unsubscribed from notifications.", "read": False},
# ]

# # Now, add the notifications to the session
# with app.app_context():
#     db.session.add_all([Notification(**note) for note in notifications])
#     db.session.commit()

ratings = [
    {"user_id": 1, "report_id": 1, "rating_value": 5},
    {"user_id": 2, "report_id": 2, "rating_value": 4},
    {"user_id": 3, "report_id": 3, "rating_value": 3},
    {"user_id": 4, "report_id": 4, "rating_value": 2},
    {"user_id": 5, "report_id": 5, "rating_value": 5},
    {"user_id": 6, "report_id": 6, "rating_value": 4},
    {"user_id": 7, "report_id": 7, "rating_value": 3},
    {"user_id": 8, "report_id": 8, "rating_value": 5},
    {"user_id": 9, "report_id": 9, "rating_value": 1}
]

# Add ratings to the session
with app.app_context():
    db.session.add_all([Rating(**rate) for rate in ratings])
    db.session.commit()

