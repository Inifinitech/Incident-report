from flask import Flask,make_response,request,jsonify,session
from flask_migrate import Migrate
from datetime import datetime, timedelta
# from flask_bcrypt import Bcrypt
from sqlalchemy import func, MetaData
from flask_cors import CORS
import os

from flask_jwt_extended import create_access_token,JWTManager, create_refresh_token, jwt_required, get_jwt_identity, current_user, verify_jwt_in_request, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps

from flask_restful import Resource,Api, reqparse
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash

from models import db, User, Report, Notification, Admin, EmergencyReport, ImageUrl, VideoUrl, Rating

app=Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] ="sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
app.config['SECRET_KEY'] = '0c3ZMJFCAm5T-NK5ZzBv50ZLuxamAllTob6uzEqRR14'
app.config['JWT_ACCESS_TOKEN_EXPIRES']=timedelta(minutes=30)
app.config['JWT_ACCESS_REFRESH_EXPIRES']=timedelta(days=30)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True


CORS(app)
migrate=Migrate(app,db)
db.init_app(app)
api=Api(app)
# bcrypt=Bcrypt(app)


# initializing JWTManager
jwt = JWTManager(app)

#  creating a custom hook that helps in knowing the roles of either the buyer or the administrator
# a method called allow that uses the user roles and give users certain rights to access certain endpoints
def allow(*roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):  
            jwt_claims=get_jwt()
            user_roles=jwt_claims.get('role',None)
            
            # Check if the user_role is in the allowed roles
            if user_roles in roles:
                return fn(*args, **kwargs)
            else:
                # creating and returning a response based on the response_body
                response_body = {"message": "Access is forbidden"}
                response = make_response(response_body, 403)
                return response

        return decorator

    return wrapper


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).first()

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
    return response


#RATING MODEL CRUD OPERATIONS
class RatingResource(Resource):
    def get(self):
        ratings = Rating.query.all()
        response = [rating.to_dict() for rating in ratings]
        return {f"Your feedback is key, see how our community is rating incident reports to help create a safer, more responsive future for everyone!": response}

    def post(self):
        # Define the post arguments parser
        post_args = reqparse.RequestParser(bundle_errors=True)
        post_args.add_argument('id', type=int, help='Error!! Add Rating id', required=True)
        post_args.add_argument('rating_value', type=int, help='Error!! Add the Rating value', required=True)
        post_args.add_argument('report_id', type=int, help='Error!! Add the Report Id associated with the Rating', required=True)
        post_args.add_argument('user_id', type=int, help='Error!! Add the User Id associated with the Rating', required=True)

        # Parse the arguments only within the context of a request
        args = post_args.parse_args()

        # Example of how you might use these values
        rating = Rating(
            id=args['id'],
            rating_value=args['rating_value'],
            report_id=args['report_id'],
            user_id=args['user_id']
        )

        # Commit to the database (assuming you have the db session set up)
        db.session.add(rating)
        db.session.commit()

        return {'message': 'Rating created successfully'}, 201


class RatingById(Resource):
    def get(self, id):
        rating = Rating.query.filter_by(id=id).first()
        if rating:
            return rating.to_dict()
        elif rating is None:
            return {"error": f"Rating with id={id} not found"}, 404
    
    def patch(self, id):
        patch_args = reqparse.RequestParser(bundle_errors=True)
        patch_args.add_argument('id', type=int, help='Error!! Add Rating id', required=True)
        patch_args.add_argument('rating_value', type=int, help='Error!! Add the Rating value', required=True)
        patch_args.add_argument('report_id', type=int, help='Error!! Add the Report Id associated with the Rating', required=True)
        patch_args.add_argument('user_id', type=int, help='Error!! Add the User Id associated with the Rating', required=True)
        args = patch_args.parse_args()

        rating = Rating.query.filter_by(id=id).first()

        if not rating:
            return {"error": f"Rating with id={id} not found"}, 404

        data = patch_args.parse_args()
        for key, value in data.items():
            if value is not None:
                setattr(rating, key, value)

        db.session.commit()

        return {
            "message": f"Rating with id {id} has been successfully edited",
            "updated_rating": rating.to_dict()
        }

    def delete(self, id):
        deleted_rating = Rating.query.filter_by(id=id).delete()
        db.session.commit()

        if deleted_rating == 0:
            return {"error": f"Sorry, the rating with id={id} has not been deleted"}, 404

        return {"detail": f"Rating with id {id} has been deleted successfully"}

#NOFICATIONS MODEL CRUD OPERATION
class NotificationResource(Resource):
    def get(self):
        notifications = Notification.query.all()
        response = [notification.to_dict() for notification in notifications]
        return {
            "notifications": response
        }
    def post(self):
        post_args = reqparse.RequestParser(bundle_errors=True)
        post_args.add_argument('id', type=int, help='Error!! Add Notification id', required=True)
        post_args.add_argument('message', type=str, help='Error!! Add the notification message', required=True)
        post_args.add_argument('read', type=bool, help='Specify if the notification is read')

        args = post_args.parse_args()

        notification = Notification(
            id=args['id'],
            message=args['message'],
            read=args['read'] if args['read'] is not None else False
        )

        db.session.add(notification)
        db.session.commit()

        return {'message': 'Notification created successfully'}, 201
    
class NotificationById(Resource):
    def get(self, id):
        notification = Notification.query.filter_by(id=id).first()
        if notification:
            return notification.to_dict()
        return {"error": f"Notification with id={id} not found"}, 404

    def patch(self, id):
        patch_args = reqparse.RequestParser(bundle_errors=True)
        patch_args.add_argument('message', type=str, help='Update the message')
        patch_args.add_argument('read', type=bool, help='Specify if the notification is read')

        args = patch_args.parse_args()

        notification = Notification.query.filter_by(id=id).first()
        if not notification:
            return {"error": f"Notification with id={id} not found"}, 404

        for key, value in args.items():
            if value is not None:
                setattr(notification, key, value)

        db.session.commit()

        return {
            "message": f"Notification with id {id} has been successfully updated",
            "updated_notification": notification.to_dict()
        }

    def delete(self, id):
        deleted_notification = Notification.query.filter_by(id=id).delete()
        db.session.commit()

        if deleted_notification == 0:
            return {"error": f"Notification with id={id} not found or not deleted"}, 404

        return {"message": f"Notification with id {id} has been deleted successfully"}
    
# User CRUD operations
class UserResource(Resource):
    def get(self):
        users = User.query.all()  # Fetch all users from the database
        response = [user.to_dict() for user in users]  # Convert to dict using the SerializerMixin
        return {"users": response}

    def post(self):
        post_args = reqparse.RequestParser(bundle_errors=True)
        post_args.add_argument('username', type=str, help='Error! Username is required', required=True)
        post_args.add_argument('email', type=str, help='Error! Email is required', required=True)
        post_args.add_argument('phone', type=str, help='Error! Phone is required', required=True)
        post_args.add_argument('password', type=str, help='Error! Password is required', required=True)
        post_args.add_argument('role', type=str, choices=['user', 'admin'], help='Error! Invalid role')
        post_args.add_argument('banned', type=bool, help='Specify if the user is banned')

        args = post_args.parse_args()

        user = User(
            username=args['username'],
            email=args['email'],
            phone=args['phone'],
            password=args['password'],
            role=args['role'] if args['role'] else 'user',
            banned=args['banned'] if args['banned'] is not None else False
        )

        db.session.add(user)
        db.session.commit()

        return {'message': 'User created successfully'}, 201


class UserById(Resource):
    def get(self, id):
        user = User.query.filter_by(id=id).first()  # Fetch user by ID
        if user:
            return user.to_dict()  # Return user as a dictionary
        return {"error": f"User with id={id} not found"}, 404

    def patch(self, id):
        patch_args = reqparse.RequestParser(bundle_errors=True)
        patch_args.add_argument('username', type=str, help='Update the username')
        patch_args.add_argument('email', type=str, help='Update the email')
        patch_args.add_argument('phone', type=str, help='Update the phone')
        patch_args.add_argument('password', type=str, help='Update the password')
        patch_args.add_argument('role', type=str, choices=['user', 'admin'], help='Update the role')
        patch_args.add_argument('banned', type=bool, help='Update banned status')

        args = patch_args.parse_args()

        user = User.query.filter_by(id=id).first()  # Fetch user by ID
        if not user:
            return {"error": f"User with id={id} not found"}, 404

        for key, value in args.items():
            if value is not None:
                setattr(user, key, value)

        db.session.commit()

        return {
            "message": f"User with id {id} has been successfully updated",
            "updated_user": user.to_dict()
        }

    def delete(self, id):
        deleted_user = User.query.filter_by(id=id).delete()  # Delete user by ID
        db.session.commit()

        if deleted_user == 0:
            return {"error": f"User with id={id} not found or not deleted"}, 404

        return {"message": f"User with id {id} has been deleted successfully"}
    
#REPORT MODEL CRUD OPERATIONS
class ReportResource(Resource):
    def get(self):
        reports = Report.query.all()  # Fetch all reports from the database
        response = [report.to_dict() for report in reports]  # Convert to dict using the SerializerMixin
        return {"reports": response}

    def post(self):
        post_args = reqparse.RequestParser(bundle_errors=True)
        post_args.add_argument('user_id', type=int, help='Error! User ID is required', required=True)
        post_args.add_argument('description', type=str, help='Error! Description is required', required=True)
        post_args.add_argument('status', type=str, choices=['under investigation', 'resolved', 'pending'], help='Error! Invalid status')
        post_args.add_argument('latitude', type=float, help='Error! Latitude is required', required=True)
        post_args.add_argument('longitude', type=float, help='Error! Longitude is required', required=True)
        post_args.add_argument('response_time', type=int, help='Response time in minutes')
        
        args = post_args.parse_args()

        report = Report(
            user_id=args['user_id'],
            description=args['description'],
            status=args['status'] if args['status'] else 'under investigation',
            latitude=args['latitude'],
            longitude=args['longitude'],
            response_time=args['response_time'] if args['response_time'] else None
        )

        db.session.add(report)
        db.session.commit()

        return {'message': 'Report created successfully'}, 201
    

class ReportById(Resource):
    def get(self, id):
        report = Report.query.filter_by(id=id).first()  
        if report:
            return report.to_dict() 
        return {"error": f"Report with id={id} not found"}, 404

    def patch(self, id):
        patch_args = reqparse.RequestParser(bundle_errors=True)
        patch_args.add_argument('description', type=str, help='Update the description')
        patch_args.add_argument('status', type=str, choices=['under investigation', 'resolved', 'pending'], help='Update the status')
        patch_args.add_argument('latitude', type=float, help='Update the latitude')
        patch_args.add_argument('longitude', type=float, help='Update the longitude')
        patch_args.add_argument('response_time', type=int, help='Update the response time')

        args = patch_args.parse_args()

        report = Report.query.filter_by(id=id).first()  
        if not report:
            return {"error": f"Report with id={id} not found"}, 404

        for key, value in args.items():
            if value is not None:
                setattr(report, key, value)

        db.session.commit()

        return {
            "message": f"Report with id {id} has been successfully updated",
            "updated_report": report.to_dict()
        }

    def delete(self, id):
        deleted_report = Report.query.filter_by(id=id).delete()  
        db.session.commit()

        if deleted_report == 0:
            return {"error": f"Report with id={id} not found or not deleted"}, 404

        return {"message": f"Report with id {id} has been deleted successfully"}

    
#ADMIN MODEL CRUD OPERATIONS
class AdminResource(Resource):
    def get(self):
        admins = Admin.query.all()  # Fetch all admin actions from the database
        response = [admin.to_dict() for admin in admins]  # Convert to dict using SerializerMixin
        return {"admins": response}

    def post(self):
        post_args = reqparse.RequestParser(bundle_errors=True)
        post_args.add_argument('incident_report_id', type=int, help='Error! Incident report ID is required')
        post_args.add_argument('emergency_only_id', type=int, help='Error! Emergency ID is required')
        post_args.add_argument('action', type=str, help='Action taken by the admin', required=True)
        post_args.add_argument('admin_id', type=int, help='Admin ID is required', required=True)
        
        args = post_args.parse_args()

        admin_act = Admin(
            incident_report_id=args['incident_report_id'],
            emergency_only_id=args['emergency_only_id'],
            action=args['action'],
            admin_id=args['admin_id']
        )

        db.session.add(admin_act)
        db.session.commit()

        return {'message': 'Admin action created successfully'}, 201


class AdminById(Resource):
    def get(self, id):
        admin = Admin.query.filter_by(id=id).first()  # Fetch admin action by ID
        if admin:
            return admin.to_dict()  # Return admin action as a dictionary
        return {"error": f"Admin action with id={id} not found"}, 404

    def patch(self, id):
        patch_args = reqparse.RequestParser(bundle_errors=True)
        patch_args.add_argument('incident_report_id', type=int, help='Update the incident report ID')
        patch_args.add_argument('emergency_only_id', type=int, help='Update the emergency ID')
        patch_args.add_argument('action', type=str, help='Update the action')
        patch_args.add_argument('admin_id', type=int, help='Update the admin ID')

        args = patch_args.parse_args()

        admin = Admin.query.filter_by(id=id).first()  # Fetch admin action by ID
        if not admin:
            return {"error": f"Admin action with id={id} not found"}, 404

        for key, value in args.items():
            if value is not None:
                setattr(admin, key, value)

        db.session.commit()

        return {
            "message": f"Admin action with id {id} has been successfully updated",
            "updated_admin_action": admin.to_dict()
        }

    def delete(self, id):
        deleted_admin = Admin.query.filter_by(id=id).delete()  # Delete admin action by ID
        db.session.commit()

        if deleted_admin == 0:
            return {"error": f"Admin action with id={id} not found or not deleted"}, 404

        return {"message": f"Admin action with id {id} has been deleted successfully"}

# class Users(Resource):
#     # @jwt_required()
#     # @allow("admin")
#     def get(self):
#         users = [user.to_dict() for user in User.query.all()]
#         return make_response(jsonify(users), 200)


# class GetUser(Resource):
#     def get(self, id):
#         user = User.query.filter(User.id == id).first()
#         if user:
#             return make_response(user.to_dict(), 200)
#         else:
#             return make_response({"message": "User not found"}, 400)
        
#     def delete(self, id):
#         user = User.query.get(id)
#         if not user:
#             return make_response({"error": "User not found!"}, 404)
        
#         db.session.delete(user)
#         db.session.commit()
#         return make_response({"message": f"{user.username} deleted!"}, 200)
    
# class BanUser(Resource):
#     def patch(self, id):
#         user = User.query.get(id)
#         if not user:
#             return {"message": "User not found"}, 404

#         user.banned = True
#         db.session.commit()
#         return {"message": "User has been banned"}, 200

# class UnbanUser(Resource):
#     def patch(self, id):
#         try:
#             user = User.query.get(id)
#             if not user:
#                 return {"message": "User not found"}, 404
            
#             user.banned = False
#             db.session.commit()
#             return {"message": "User has been unbanned"}, 200
        
#         except Exception as e:
#             print(f"Error unbanning user: {e}")
#             return {"error": str(e)}, 500

# class BanUser(Resource):
#     def patch(self, id):
#         user = User.query.get(id)
#         if not user:
#             return {"message": "User not found"}, 404

#         user.banned = True
#         db.session.commit()
#         return {"message": "User has been banned"}, 200

# class UnbanUser(Resource):
#     def patch(self, id):
#         try:
#             user = User.query.get(id)
#             if not user:
#                 return {"message": "User not found"}, 404
            
#             user.banned = False
#             db.session.commit()
#             return {"message": "User has been unbanned"}, 200
        
#         except Exception as e:
#             print(f"Error unbanning user: {e}")
#             return {"error": str(e)}, 500

# # endpoints
# class Signup(Resource):
#     def post(self):
#         # Get JSON data from the request
#         data = request.get_json()

#         # Check if all necessary fields are provided
#         if not all([data.get('username'), data.get('email'),data.get('phone'), data.get('password')]):
#             return make_response(jsonify({"message": "Missing required fields"}), 400)
        
#         # Validate email format
#         if "@" not in data["email"]:
#             # creating and returning a response based on the response body
#             response_body ={"message": "Please include an '@' in the email address."}
#             response = make_response(response_body, 400)
#             return response

#         # Check if email already exists in the database
#         if User.query.filter_by(email=data["email"]).first():
#             # creating and returning a response based on the response body
#             response_body ={"message": "Email already exists"}
#             response = make_response(response_body, 400)
#             return response

#         password = generate_password_hash(data["password"])

#         # Create new user
#         new_user = User(
#             username=data.get('username'),
#             phone=data.get('phone'),
#             email=data.get('email'),
#             password=password,
#             role=data.get('role', 'user'),
#         )

#         try:
#             db.session.add(new_user)
#             db.session.commit()
#             return make_response(jsonify({"message": "User added successfully"}), 201)
#         except Exception as e:
#             db.session.rollback()
#             return make_response(jsonify({"message": "Error creating user", "error": str(e)}), 500)
        




# # incident reports endpoint
    
# class Incident(Resource):
#     def post(self):
#         data = request.get_json()

#         user_id = data.get('user_id')
#         user = User.query.get(user_id)
        
#         # Check if the user exists and if they are banned
#         if not user:
#             return make_response(jsonify({"error": "User not found"}), 404)
#         if user.banned:
#             return make_response(jsonify({"error": "User is banned and cannot post incidents"}), 403)

#         new_incident = Report (
#             user_id = data.get('user_id'),
#             description = data.get('description'),
#             status = data.get('status'),
#             latitude=data.get('latitude'),
#             longitude=data.get('longitude'),
#         )

#         db.session.add(new_incident)
#         db.session.commit()
        
#         print(f"New Incident Created: {new_incident.to_dict()}")
#         return make_response(new_incident.to_dict(), 201)
    
#     def get(self):        
#         incidents = [incident.to_dict() for incident in Report.query.all()]
        
#         return make_response(jsonify(incidents), 200)
    
# class GetIncidentId(Resource):
#     def get(self, id):

#         incident = Report.query.filter(Report.id==id).first()
#         if incident:
#             incident_dict = incident.to_dict()
#             return incident_dict
    
# class UpdateIncident(Resource):
    
#     def patch(self, id):
#         data = request.get_json()


#         incident = Report.query.get(id)
#         if not incident:
#             return make_response({"error": "Incident not found!"}, 404)
#         description = data.get('description')
        
#         if incident:
#             incident.description = description
#             db.session.add(incident)
#             db.session.commit()
#             return make_response('Item updated successfully')
        
# class UpdateIncidentStatus(Resource):
#     def patch(self, id):
#         data = request.get_json()

#         new_status = data.get('status')


#         incident = Report.query.get(id)
#         if not incident:
#             return make_response({"error": "Incident not found!"}, 404)

#         if new_status in ['under investigation', 'resolved', 'rejected']:
#             incident.status = new_status
#             db.session.commit()
#             return make_response({"message": "Status Updated successfully", "incident": incident.to_dict()}, 200)
        
#         else:
#             return make_response({"error": "Invalid status"})
        

# class DeleteIncident(Resource):
    
#     def delete(self, id):

#         incident_del = Report.query.get(id)
#         db.session.delete(incident_del)
#         db.session.commit()

#         return make_response('Incident deleted')
    
# # incident media endpoint
# class MediaPost(Resource):
#     def post(self):
#         data = request.get_json()
#         incident_report_id = data.get('incident_report_id')

#         if data.get('media_image'):
#             new_image = ImageUrl(
#                 incident_report_id=incident_report_id,
#                 media_image=data.get('media_image')
#             )
#             db.session.add(new_image)

#         if data.get('media_video'):
#             new_video = VideoUrl(
#                 incident_report_id=incident_report_id,
#                 media_video=data.get('media_video')
#             )
#             db.session.add(new_video)

#         db.session.commit()

#         return make_response({"message": "Media added!"}, 201)

    
# class MediaDelete(Resource):
#     def delete(self, id):

#         media_image = ImageUrl.query.get(id)
#         media_video = VideoUrl.query.get(id)
#         db.session.delete(media_image)
#         db.session.delete(media_video)
#         db.session.commit()

#         return make_response('Media deleted!!')
    
# class RatingResource(Resource):
#     def get(self):
#         ratings = Rating.query.all()
#         response = [rating.to_dict() for rating in ratings]
#         return {"message": response}

#     def post(self):
#         # Define the post arguments parser
#         post_args = reqparse.RequestParser(bundle_errors=True)
#         post_args.add_argument('id', type=int, help='Error!! Add Rating id', required=True)
#         post_args.add_argument('rating_value', type=int, help='Error!! Add the Rating value', required=True)
#         post_args.add_argument('report_id', type=int, help='Error!! Add the Report Id associated with the Rating', required=True)
#         post_args.add_argument('user_id', type=int, help='Error!! Add the User Id associated with the Rating', required=True)

#         # Parse the arguments only within the context of a request
#         args = post_args.parse_args()

#         # Example of how you might use these values
#         rating = Rating(
#             id=args['id'],
#             rating_value=args['rating_value'],
#             report_id=args['report_id'],
#             user_id=args['user_id']
#         )

#         # Commit to the database (assuming you have the db session set up)
#         db.session.add(rating)
#         db.session.commit()

#         return {'message': 'Rating created successfully'}, 201
    
# class EmergencyPost(Resource):
#     def get(self):
#         emergencies = [emergency.to_dict() for emergency in EmergencyReport.query.all()]
#         return make_response(jsonify(emergencies), 200)

#     def post(self):
#         data = request.get_json()

#         emergency_report = EmergencyReport(
#             name = data.get('name'),
#             description = data.get('description'),
#             status = data.get('status'),
#             latitude=data.get('latitude'),
#             longitude=data.get('longitude'),
#             phone=data.get('phone')
#         ) 
#         db.session.add(emergency_report)
#         db.session.commit()

#         return make_response({"message": "Emergency posted successfully"}, 201)
    
    
    
# # endpoints for notifications

# # class GetNotifications(Resource):
# #     def get(self):
# #         notifications = Notification.query.all()
# #         notifications_dict = notifications.to_dict()
# #         return notifications_dict
    
# #     def post(self):
# #         data = request.get_json()

# #         new_notification = Notification(
# #             user_id = data.get('user_id'),
# #             message = data.get('message'),
# #             read = data.get('read')
# #         )

# #         db.session.add(new_notification)
# #         db.session.commit()
# #         return make_response('Notification added automatically!!')

# # endpoints for admin actions

# class AdminIncidents(Resource):
#     def get(self):
        
#         incidents = [incident.to_dict() for incident in Admin.query.all()]
#         return make_response(jsonify(incidents), 200)
    
# class PostAdminIncidents(Resource):
#     def post(self):
#         data = request.get_json()

#         new_action = Admin (
#             incident_report_id = data.get('incident_report_id'),
#             action = data.get('action')
#         )

#         db.session.add(new_action)
#         db.session.commit()

#         return make_response('Action recorded!!')
    
# class Analytics(Resource):
#     def get(self):
#         try:
#             # For example, fetching the number of incidents in the last 30 days
#             incident_trends = db.session.query(func.count(Report.id)) \
#                 .filter(Report.created_at >= datetime.utcnow() - timedelta(days=30)) \
#                 .scalar()

#             # Geographic distribution (count of incidents per location)
#             geo_dist = db.session.query(Report.latitude, Report.longitude, func.count(Report.id).label('count')) \
#                 .group_by(Report.latitude, Report.longitude).all()

#             # Convert geo_dist tuples into dictionaries
#             geo_dist = [{"latitude": lat, "longitude": lon, "count": count} for lat, lon, count in geo_dist]

#             # Response times (average response time for incidents)
#             avg_response_time = db.session.query(func.avg(Report.response_time)).scalar()

#             # Recent Activity (latest user activity)
#             recent_activity = db.session.query(User.username, Report.description, Report.status, Report.created_at) \
#                 .join(Report).order_by(Report.created_at.desc()).limit(5).all()

#             # Convert recent_activity tuples into dictionaries
#             recent_activity = [{
#                 "username": username,
#                 "description": description,
#                 "status": status,
#                 "created_at": created_at.isoformat()  # Convert datetime to string
#             } for username, description, status, created_at in recent_activity]

#             # Prepare data for front-end
#             response_data = {
#                 "incident_trends": incident_trends,
#                 "geo_dist": geo_dist,
#                 "avg_response_time": avg_response_time,
#                 "recent_activity": recent_activity
#             }

#             return make_response(jsonify(response_data), 200)
        
#         except Exception as e:
#             return make_response(jsonify({"error": str(e)}), 500)
    
# # class UpdateAdminIncidents(Resource):
# #     def patch(self, id):
# #         data = request.get_json()

# #         incident = Admin.query.get(id)
# #         action = data.get('action')

# #         if incident:
# #             incident.action = action
# #             db.session.add(incident)
# #             db.session.commit()
# #             return make_response('Action updated!!')

# class Login(Resource):
#     def post(self):
#         data = request.get_json()
#         email = data["email"]

#         user = User.query.filter_by(email=email).first()

#         if not user:
#             return make_response({"message": f"User with email {email} does not exist"}, 404)
        
#         if not check_password_hash(user.password, data["password"]):
#             return make_response({"message": "The password entered is incorrect"}, 403)
        
#         # creating an access and a refresh token
#         access_token = create_access_token(identity=user.id, additional_claims={"role": user.role})
#         refresh_token = create_refresh_token(identity=user.id)

#         user1 = user.to_dict()

#         return{
#             "message": "Logged in",
#             "user_data": user1,
#             "access_token": access_token,
#             "refresh_token": refresh_token,
#             "role": user.role
#         }
#     #  a method to refresh the token
#     @jwt_required(refresh = True)
#     def get(self):
#         identity = get_jwt_identity()
#         access_token = create_access_token(identity=identity)
#         response = jsonify(access_token=access_token)
#         return response
        




# api.add_resource(GetUser, '/user/<int:id>')
# api.add_resource(Users, '/users')
# api.add_resource(Signup, '/signup')
# api.add_resource(Login, '/login')
# api.add_resource(BanUser,'/users/<int:id>/ban')
# api.add_resource(UnbanUser, '/users/<int:id>/unban')

# # routes for incident
# api.add_resource(Incident, '/incidents')
# api.add_resource(GetIncidentId, '/gets-incident/<int:id>')
# api.add_resource(UpdateIncident, '/updates-incident/<int:id>')
# api.add_resource(DeleteIncident, '/deletes-incident/<int:id>')

# # route for emergency
# api.add_resource(EmergencyPost, '/emergency-reporting')

# # routes for media
# api.add_resource(MediaPost, '/media')
# api.add_resource(MediaDelete, '/media/<int:id>')

# # routes for admin actions
# api.add_resource(AdminIncidents, '/admin/reports')
# # api.add_resource(UpdateAdminIncidents, '/admin/status/<int:id>')
# api.add_resource(UpdateIncidentStatus, '/incident/<int:id>/status')
# api.add_resource(PostAdminIncidents, '/admin/status')

# # route for rating
# api.add_resource(RatingResource, '/ratings')

# routes for admin analytics
# api.add_resource(Analytics, '/analytics')




#RATING MODELS ROUTES
api.add_resource(RatingResource, '/ratings')
api.add_resource(RatingById, '/rating/<int:id>')

#NOTIFICATION MODEL ROUTES
api.add_resource(NotificationResource, '/notifications')
api.add_resource(NotificationById, '/notification/<int:id>')

# USER MODEL ROUTES
api.add_resource(UserResource, '/users')  
api.add_resource(UserById, '/user/<int:id>')  

#REPORT CRUD MODEL ROUTES
api.add_resource(ReportResource, '/reports')
api.add_resource(ReportById, '/report/<int:id>')


#ADMIN MODEL CRUD ROUTES
api.add_resource(AdminResource, '/admins')  
api.add_resource(AdminById, '/admin/<int:id>') 




if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5555))
    app.run(host="0.0.0.0", port=port, debug=True)