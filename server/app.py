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


# Rating CRUD operations
class RatingResource(Resource):
    def get(self):
        ratings = Rating.query.all()  
        response = [rating.to_dict() for rating in ratings]  
        return {"ratings": response}

    def post(self):
        post_args = reqparse.RequestParser(bundle_errors=True)
        post_args.add_argument('user_id', type=int, help='Error! User ID is required', required=True)
        post_args.add_argument('report_id', type=int, help='Error! Report ID is required', required=True)
        post_args.add_argument('rating_value', type=int, help='Error! Rating value is required', required=True)
        post_args.add_argument('feedback', type=str, help='Error! Feedback is required', required=True) 

        args = post_args.parse_args()

        rating = Rating(
            user_id=args['user_id'],
            report_id=args['report_id'],
            rating_value=args['rating_value'],
            feedback=args['feedback'] 
        )

        db.session.add(rating)
        db.session.commit()

        return {'message': 'Rating created successfully'}, 201


class RatingById(Resource):
    def get(self, id):
        rating = Rating.query.filter_by(id=id).first()  
        if rating:
            return rating.to_dict()  
        return {"error": f"Rating with id={id} not found"}, 404

    def patch(self, id):
        patch_args = reqparse.RequestParser(bundle_errors=True)
        patch_args.add_argument('rating_value', type=int, help='Update the rating value')
        patch_args.add_argument('feedback', type=str, help='Update the feedback')  

        args = patch_args.parse_args()

        rating = Rating.query.filter_by(id=id).first() 
        if not rating:
            return {"error": f"Rating with id={id} not found"}, 404

        for key, value in args.items():
            if value is not None:
                setattr(rating, key, value)

        db.session.commit()

        return {
            "message": f"Rating with id {id} has been successfully updated",
            "updated_rating": rating.to_dict()
        }

    def delete(self, id):
        deleted_rating = Rating.query.filter_by(id=id).delete() 
        db.session.commit()

        if deleted_rating == 0:
            return {"error": f"Rating with id={id} not found or not deleted"}, 404

        return {"message": f"Rating with id {id} has been deleted successfully"}
    


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
        users = User.query.all()  
        response = [user.to_dict() for user in users]  
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
        user = User.query.filter_by(id=id).first()  
        if user:
            return user.to_dict() 
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

        user = User.query.filter_by(id=id).first() 
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
        deleted_user = User.query.filter_by(id=id).delete()  
        db.session.commit()

        if deleted_user == 0:
            return {"error": f"User with id={id} not found or not deleted"}, 404

        return {"message": f"User with id {id} has been deleted successfully"}
    
#REPORT MODEL CRUD OPERATIONS
class ReportResource(Resource):
    def get(self):
        reports = Report.query.all()  
        response = [report.to_dict() for report in reports]  
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
        admins = Admin.query.all()  
        response = [admin.to_dict() for admin in admins]  
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
        admin = Admin.query.filter_by(id=id).first()  
        if admin:
            return admin.to_dict() 
        return {"error": f"Admin action with id={id} not found"}, 404

    def patch(self, id):
        patch_args = reqparse.RequestParser(bundle_errors=True)
        patch_args.add_argument('incident_report_id', type=int, help='Update the incident report ID')
        patch_args.add_argument('emergency_only_id', type=int, help='Update the emergency ID')
        patch_args.add_argument('action', type=str, help='Update the action')
        patch_args.add_argument('admin_id', type=int, help='Update the admin ID')

        args = patch_args.parse_args()

        admin = Admin.query.filter_by(id=id).first() 
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
        deleted_admin = Admin.query.filter_by(id=id).delete()  
        db.session.commit()

        if deleted_admin == 0:
            return {"error": f"Admin action with id={id} not found or not deleted"}, 404

        return {"message": f"Admin action with id {id} has been deleted successfully"}
    

# IMAGEURL MODEL CRUD OPERATIONS
class ImageUrlResource(Resource):
    def get(self):
        images = ImageUrl.query.all()  
        response = [image.to_dict() for image in images] 
        return {"images": response}

    def post(self):
        post_args = reqparse.RequestParser(bundle_errors=True)
        post_args.add_argument('incident_report_id', type=int, help='Error! Incident report ID is required', required=True)
        post_args.add_argument('media_image', type=str, help='Error! Media image URL is required', required=True)
        
        args = post_args.parse_args()

        image = ImageUrl(
            incident_report_id=args['incident_report_id'],
            media_image=args['media_image']
        )

        db.session.add(image)
        db.session.commit()

        return {'message': 'Image uploaded successfully'}, 201


class ImageUrlById(Resource):
    def get(self, id):
        image = ImageUrl.query.filter_by(id=id).first()  
        if image:
            return image.to_dict()  
        return {"error": f"Image with id={id} not found"}, 404

    def patch(self, id):
        patch_args = reqparse.RequestParser(bundle_errors=True)
        patch_args.add_argument('incident_report_id', type=int, help='Update the incident report ID')
        patch_args.add_argument('media_image', type=str, help='Update the media image URL')

        args = patch_args.parse_args()

        image = ImageUrl.query.filter_by(id=id).first()  
        if not image:
            return {"error": f"Image with id={id} not found"}, 404

        for key, value in args.items():
            if value is not None:
                setattr(image, key, value)

        db.session.commit()

        return {
            "message": f"Image with id {id} has been successfully updated",
            "updated_image": image.to_dict()
        }

    def delete(self, id):
        deleted_image = ImageUrl.query.filter_by(id=id).delete()  
        db.session.commit()

        if deleted_image == 0:
            return {"error": f"Image with id={id} not found or not deleted"}, 404

        return {"message": f"Image with id {id} has been deleted successfully"}


# VIDEOURL MODEL CRUD OPERATIONS
class VideoUrlResource(Resource):
    def get(self):
        videos = VideoUrl.query.all()  
        response = [video.to_dict() for video in videos]  
        return {"videos": response}

    def post(self):
        post_args = reqparse.RequestParser(bundle_errors=True)
        post_args.add_argument('incident_report_id', type=int, help='Error! Incident report ID is required', required=True)
        post_args.add_argument('media_video', type=str, help='Error! Media video URL is required', required=True)
        
        args = post_args.parse_args()

        video = VideoUrl(
            incident_report_id=args['incident_report_id'],
            media_video=args['media_video']
        )

        db.session.add(video)
        db.session.commit()

        return {'message': 'Video uploaded successfully'}, 201


class VideoUrlById(Resource):
    def get(self, id):
        video = VideoUrl.query.filter_by(id=id).first()  
        if video:
            return video.to_dict()  
        return {"error": f"Video with id={id} not found"}, 404

    def patch(self, id):
        patch_args = reqparse.RequestParser(bundle_errors=True)
        patch_args.add_argument('incident_report_id', type=int, help='Update the incident report ID')
        patch_args.add_argument('media_video', type=str, help='Update the media video URL')

        args = patch_args.parse_args()

        video = VideoUrl.query.filter_by(id=id).first()  
        if not video:
            return {"error": f"Video with id={id} not found"}, 404

        for key, value in args.items():
            if value is not None:
                setattr(video, key, value)

        db.session.commit()

        return {
            "message": f"Video with id {id} has been successfully updated",
            "updated_video": video.to_dict()
        }

    def delete(self, id):
        deleted_video = VideoUrl.query.filter_by(id=id).delete()  
        db.session.commit()

        if deleted_video == 0:
            return {"error": f"Video with id={id} not found or not deleted"}, 404

        return {"message": f"Video with id {id} has been deleted successfully"}
    

# EMERGENCYREPORT MODEL CRUD OPERATIONS
class EmergencyReportResource(Resource):
    def get(self):
        emergencies = EmergencyReport.query.all()  
        response = [emergency.to_dict() for emergency in emergencies] 
        return {"emergencies": response}

    def post(self):
        post_args = reqparse.RequestParser(bundle_errors=True)
        post_args.add_argument('name', type=str, help='Error! Name is required', required=True)
        post_args.add_argument('description', type=str, help='Error! Description is required', required=True)
        post_args.add_argument('status', type=str, help='Error! Status is required', default='under investigation')
        post_args.add_argument('latitude', type=float, help='Error! Latitude is required', required=True)
        post_args.add_argument('longitude', type=float, help='Error! Longitude is required', required=True)
        post_args.add_argument('phone', type=int, help='Error! Phone number is required', required=True)
        
        args = post_args.parse_args()

        emergency = EmergencyReport(
            name=args['name'],
            description=args['description'],
            status=args['status'],
            latitude=args['latitude'],
            longitude=args['longitude'],
            phone=args['phone']
        )

        db.session.add(emergency)
        db.session.commit()

        return {'message': 'Emergency report created successfully'}, 201


class EmergencyReportById(Resource):
    def get(self, id):
        emergency = EmergencyReport.query.filter_by(id=id).first()  
        if emergency:
            return emergency.to_dict() 
        return {"error": f"Emergency report with id={id} not found"}, 404

    def patch(self, id):
        patch_args = reqparse.RequestParser(bundle_errors=True)
        patch_args.add_argument('name', type=str, help='Update the name')
        patch_args.add_argument('description', type=str, help='Update the description')
        patch_args.add_argument('status', type=str, help='Update the status')
        patch_args.add_argument('latitude', type=float, help='Update the latitude')
        patch_args.add_argument('longitude', type=float, help='Update the longitude')
        patch_args.add_argument('phone', type=int, help='Update the phone number')

        args = patch_args.parse_args()

        emergency = EmergencyReport.query.filter_by(id=id).first()  
        if not emergency:
            return {"error": f"Emergency report with id={id} not found"}, 404

        for key, value in args.items():
            if value is not None:
                setattr(emergency, key, value)

        db.session.commit()

        return {
            "message": f"Emergency report with id {id} has been successfully updated",
            "updated_report": emergency.to_dict()
        }

    def delete(self, id):
        deleted_report = EmergencyReport.query.filter_by(id=id).delete()  
        db.session.commit()

        if deleted_report == 0:
            return {"error": f"Emergency report with id={id} not found or not deleted"}, 404

        return {"message": f"Emergency report with id {id} has been deleted successfully"}

    



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

#IMAGEURL MODEL  CRUD ROUTES
api.add_resource(ImageUrlResource, '/images')  
api.add_resource(ImageUrlById, '/image/<int:id>')

#VIDEOURL CRUD ROUTES
api.add_resource(VideoUrlResource, '/videos')  
api.add_resource(VideoUrlById, '/video/<int:id>')

# EMERGENCYREPORT CRUD ROUTES
api.add_resource(EmergencyReportResource, '/emergencies')  
api.add_resource(EmergencyReportById, '/emergency/<int:id>')



if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5555))
    app.run(host="0.0.0.0", port=port, debug=True)