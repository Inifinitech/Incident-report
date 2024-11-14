from flask import Flask,make_response,request,jsonify,session,request
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_restful import Resource, Api, reqparse
from models import db, User, Report, Admin, Media, Notification, Rating

from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt
from sqlalchemy import func
from flask_cors import CORS
import os

from flask_restful import Resource,Api
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash



app=Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] ="sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

migrate=Migrate(app,db)
db.init_app(app)
api=Api(app)
bcrypt=Bcrypt(app)
CORS(app)


from flask_restful import reqparse

# Arguments for PATCH (partial updates)
patch_args = reqparse.RequestParser(bundle_errors=True)
patch_args.add_argument('id', type=int, help='Error!! Add the Id of the Rating')
patch_args.add_argument('rating', type=int, help='Error!! Add the Rating value')
patch_args.add_argument('feedback', type=str, help='Error!! Add Feedback for the Rating')
patch_args.add_argument('report_id', type=int, help='Error!! Add the Report Id associated with the Rating')

# Arguments for POST (creating new entries)
post_args = reqparse.RequestParser(bundle_errors=True)
post_args.add_argument('rating', type=int, help='Error!! Add the Rating value', required=True)
post_args.add_argument('feedback', type=str, help='Error!! Add Feedback for the Rating', required=False)
post_args.add_argument('report_id', type=int, help='Error!! Add the Report Id associated with the Rating', required=True)

class RatingResource(Resource):
    def get(self):
        ratings = Rating.query.all()
        response = [rating.to_dict() for rating in ratings]
        return {"ratings": response}

    def post(self):
        # Using request.get_json() to handle incoming data
        data = request.get_json()

        # Extract data from the incoming JSON body
        rating_value = data.get('rating')
        feedback = data.get('feedback')
        report_id = data.get('report_id')

        # Check if required fields are present
        if not rating_value or not report_id:
            return {"message": "Rating and report_id are required"}, 400

        # Create a new Rating object
        new_rating = Rating(rating=rating_value, feedback=feedback, report_id=report_id)

        # Add the new rating to the database
        db.session.add(new_rating)
        db.session.commit()

        # Return a success response
        return {"message": "Rating added successfully", "rating": new_rating.to_dict()}, 201
# class RatingResource(Resource):
#     def get(self):
#         ratings = Rating.query.all()
#         response = [rating.to_dict() for rating in ratings]
#         return response

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')  # Or specify specific origin
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
    return response

# endpoints
class Signup(Resource):
    def post(self):
        # Get JSON data from the request
        data = request.get_json()

        # Check if all necessary fields are provided
        if not all([data.get('username'), data.get('email'), data.get('password')]):
            return make_response(jsonify({"message": "Missing required fields"}), 400)

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(data.get('password'))

        # Create new user
        new_user = User(
            username=data.get('username'),
            email=data.get('email'),
            password=hashed_password,
            role=data.get('role', 'user'),
        )

        try:
            db.session.add(new_user)
            db.session.commit()
            return make_response(jsonify({"message": "User added successfully"}), 201)
        except Exception as e:
            db.session.rollback()
            return make_response(jsonify({"message": "Error creating user", "error": str(e)}), 500)
        

class Login(Resource):
    def post(self):
        data = request.get_json()
        
        if not data or 'email' not in data or 'password' not in data:
            return make_response(jsonify({"message": "Email and password are required"}), 400)

        user = User.query.filter_by(email=data['email']).first()

        if user and bcrypt.check_password_hash(user.password, data['password']):
            return make_response('Logged in successfully!', 200)
        return make_response('Check credentials', 401)


# incident reports endpoint
    
class Incident(Resource):
    def post(self):
        data = request.get_json()

        new_incident = Report (
            user_id = data.get('user_id'),
            title = data.get('title'),
            description = data.get('description'),
            status = data.get('status'),
            latitude=data.get('latitude'),
            longitude=data.get('longitude'),
        )

        db.session.add(new_incident)
        db.session.commit()

        return make_response('Incident posted!!', 201)
    
    def get(self):
        
        incidents = [incident.to_dict() for incident in Report.query.all()]
        
        return make_response(jsonify(incidents), 200)
    
class GetIncidentId(Resource):
    def get(self, id):

        incident = Report.query.filter(Report.id==id).first()
        if incident:
            incident_dict = incident.to_dict()
            return incident_dict
    
class UpdateIncident(Resource):
    
    def patch(self, id):
        data = request.get_json()

        incident = Report.query.get(id)
        title = data.get('title')
        description = data.get('description')
        
        if incident:
            incident.title = title
            incident.description = description
            db.session.add(incident)
            db.session.commit()
            return make_response('Item updated successfully')



    
class DeleteIncident(Resource):
    
    def delete(self, id):

        incident_del = Report.query.get(id)
        db.session.delete(incident_del)
        db.session.commit()

        return make_response('Incident deleted')
    
# incident media endpoint

class MediaPost(Resource):
    def post(self):
        data = request.get_json()

        new_media = Media (
            incident_report_id = data.get('incident_report_id'),
            media_type = data.get('media_type'),
            media_url = data.get('media_url')
        )

        db.session.add(new_media)
        db.session.commit()

        return make_response('Media added!!')
    
class MediaDelete(Resource):
    def delete(self, id):

        media_del = Media.query.get(id)
        db.session.delete(media_del)
        db.session.commit()

        return make_response('Media deleted!!')
    
# endpoints for notifications

# class GetNotifications(Resource):
#     def get(self):
#         notifications = Notification.query.all()
#         notifications_dict = notifications.to_dict()
#         return notifications_dict
    
#     def post(self):
#         data = request.get_json()

#         new_notification = Notification(
#             user_id = data.get('user_id'),
#             message = data.get('message'),
#             read = data.get('read')
#         )

#         db.session.add(new_notification)
#         db.session.commit()
#         return make_response('Notification added automatically!!')

# endpoints for admin actions

class AdminIncidents(Resource):
    def get(self):
        
        incidents = [incident.to_dict() for incident in Admin.query.all()]
        return make_response(jsonify(incidents), 200)
    
class PostAdminIncidents(Resource):
    def post(self):
        data = request.get_json()

        new_action = Admin (
            incident_report_id = data.get('incident_report_id'),
            action = data.get('action')
        )

        db.session.add(new_action)
        db.session.commit()

        return make_response('Action recorded!!')

    
class UpdateAdminIncidents(Resource):
    def patch(self, id):
        data = request.get_json()

        incident = Admin.query.get(id)
        action = data.get('action')

        if incident:
            incident.action = action
            db.session.add(incident)
            db.session.commit()
            return make_response('Action updated!!')
        





api.add_resource(Signup, '/signup')
api.add_resource(Login, '/login')

# routes for incident
api.add_resource(Incident, '/incidents')
api.add_resource(GetIncidentId, '/gets-incident/<int:id>')
api.add_resource(UpdateIncident, '/updates-incident/<int:id>')
api.add_resource(DeleteIncident, '/deletes-incident/<int:id>')

# routes for media
api.add_resource(MediaPost, '/media')
api.add_resource(MediaDelete, '/media/<int:id>')

# routes for admin actions
api.add_resource(AdminIncidents, '/admin/reports')
api.add_resource(UpdateAdminIncidents, '/admin/status/<int:id>')
api.add_resource(PostAdminIncidents, '/admin/status')


# routes for notifications
# api.add_resource(GetNotifications, '/notifications')


#routes for rating
api.add_resource(RatingResource, '/ratings')







if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5555))
    app.run(host="0.0.0.0", port=port, debug=True)

        
