from flask import Flask,make_response,request,jsonify,session
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from datetime import datetime, timedelta
from flask_bcrypt import Bcrypt
from sqlalchemy import func
from flask_cors import CORS
import os

from flask_restful import Resource,Api
from sqlalchemy.exc import SQLAlchemyError
from werkzeug.security import generate_password_hash

from models import db, User, Report, Notification, Admin, EmergencyReport, ImageUrl, VideoUrl

app=Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] ="sqlite:///app.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = True

migrate=Migrate(app,db)
db.init_app(app)
api=Api(app)
bcrypt=Bcrypt(app)
CORS(app)

@app.after_request
def after_request(response):
    response.headers.add('Access-Control-Allow-Origin', '*')  # Or specify specific origin
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, PATCH, OPTIONS')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With')
    return response

class Users(Resource):
    def get(self):
        users = [user.to_dict() for user in User.query.all()]
        return make_response(jsonify(users), 200)


class GetUser(Resource):
    def get(self, id):
        user = User.query.filter(User.id == id).first()
        if user:
            return make_response(user.to_dict(), 200)
        else:
            return make_response({"message": "User not found"}, 400)
        
    def delete(self, id):
        user = User.query.get(id)
        if not user:
            return make_response({"error": "User not found!"}, 404)
        
        db.session.delete(user)
        db.session.commit()
        return make_response({"message": f"{user.username} deleted!"}, 200)

class BanUser(Resource):
    def patch(self, id):
        user = User.query.get(id)
        if not user:
            return {"message": "User not found"}, 404

        user.banned = True
        db.session.commit()
        return {"message": "User has been banned"}, 200

class UnbanUser(Resource):
    def patch(self, id):
        try:
            user = User.query.get(id)
            if not user:
                return {"message": "User not found"}, 404
            
            user.banned = False
            db.session.commit()
            return {"message": "User has been unbanned"}, 200
        
        except Exception as e:
            print(f"Error unbanning user: {e}")
            return {"error": str(e)}, 500

# endpoints
class Signup(Resource):
    def post(self):
        # Get JSON data from the request
        data = request.get_json()

        # Check if all necessary fields are provided
        if not all([data.get('username'), data.get('email'),data.get('phone'), data.get('password')]):
            return make_response(jsonify({"message": "Missing required fields"}), 400)

        # Hash the password
        hashed_password = bcrypt.generate_password_hash(data.get('password'))

        # Create new user
        new_user = User(
            username=data.get('username'),
            phone=data.get('phone'),
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

        if user and bcrypt.check_password_hash(user.password, data.get('password')):

            return make_response(user.to_dict(), 201)
        
        return make_response('Check credentials', 401)


# incident reports endpoint
    
class Incident(Resource):
    def post(self):
        data = request.get_json()

         # Retrieve the user from the database
        user_id = data.get('user_id')
        user = User.query.get(user_id)
        
        # Check if the user exists and if they are banned
        if not user:
            return make_response(jsonify({"error": "User not found"}), 404)
        if user.banned:
            return make_response(jsonify({"error": "User is banned and cannot post incidents"}), 403)


        new_incident = Report (
            user_id = data.get('user_id'),
            description = data.get('description'),
            status = data.get('status'),
            latitude=data.get('latitude'),
            longitude=data.get('longitude'),
        )

        db.session.add(new_incident)
        db.session.commit()
        
        print(f"New Incident Created: {new_incident.to_dict()}")
        return make_response(new_incident.to_dict(), 201)
    
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
        if not incident:
            return make_response({"error": "Incident not found!"}, 404)
        description = data.get('description')
        
        if incident:
            incident.description = description
            db.session.add(incident)
            db.session.commit()
            return make_response('Item updated successfully')
        
class UpdateIncidentStatus(Resource):
    def patch(self, id):
        data = request.get_json()

        new_status = data.get('status')


        incident = Report.query.get(id)
        if not incident:
            return make_response({"error": "Incident not found!"}, 404)

        if new_status in ['under investigation', 'resolved', 'rejected']:
            incident.status = new_status
            db.session.commit()
            return make_response({"message": "Status Updated successfully", "incident": incident.to_dict()}, 200)
        
        else:
            return make_response({"error": "Invalid status"})
        

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
        incident_report_id = data.get('incident_report_id')

        if data.get('media_image'):
            new_image = ImageUrl(
                incident_report_id=incident_report_id,
                media_image=data.get('media_image')
            )
            db.session.add(new_image)

        if data.get('media_video'):
            new_video = VideoUrl(
                incident_report_id=incident_report_id,
                media_video=data.get('media_video')
            )
            db.session.add(new_video)

        db.session.commit()

        return make_response({"message": "Media added!"}, 201)

    
class MediaDelete(Resource):
    def delete(self, id):

        media_image = ImageUrl.query.get(id)
        media_video = VideoUrl.query.get(id)
        db.session.delete(media_image)
        db.session.delete(media_video)
        db.session.commit()

        return make_response('Media deleted!!')
    
class EmergencyPost(Resource):
    def get(self):
        emergencies = [emergency.to_dict() for emergency in EmergencyReport.query.all()]
        return make_response(jsonify(emergencies), 200)

    def post(self):
        data = request.get_json()

        emergency_report = EmergencyReport(
            name = data.get('name'),
            description = data.get('description'),
            status = data.get('status'),
            latitude=data.get('latitude'),
            longitude=data.get('longitude'),
            phone=data.get('phone')
        ) 
        db.session.add(emergency_report)
        db.session.commit()

        return make_response({"message": "Emergency posted successfully"}, 201)
    
    
    
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
    
class Analytics(Resource):
    def get(self):
        try:
            # For example, fetching the number of incidents in the last 30 days
            incident_trends = db.session.query(func.count(Report.id)) \
                .filter(Report.created_at >= datetime.utcnow() - timedelta(days=30)) \
                .scalar()

            # Geographic distribution (count of incidents per location)
            geo_dist = db.session.query(Report.latitude, Report.longitude, func.count(Report.id).label('count')) \
                .group_by(Report.latitude, Report.longitude).all()

            # Convert geo_dist tuples into dictionaries
            geo_dist = [{"latitude": lat, "longitude": lon, "count": count} for lat, lon, count in geo_dist]

            # Response times (average response time for incidents)
            avg_response_time = db.session.query(func.avg(Report.response_time)).scalar()

            # Recent Activity (latest user activity)
            recent_activity = db.session.query(User.username, Report.description, Report.status, Report.created_at) \
                .join(Report).order_by(Report.created_at.desc()).limit(5).all()

            # Convert recent_activity tuples into dictionaries
            recent_activity = [{
                "username": username,
                "description": description,
                "status": status,
                "created_at": created_at.isoformat()  # Convert datetime to string
            } for username, description, status, created_at in recent_activity]

            # Prepare data for front-end
            response_data = {
                "incident_trends": incident_trends,
                "geo_dist": geo_dist,
                "avg_response_time": avg_response_time,
                "recent_activity": recent_activity
            }

            return make_response(jsonify(response_data), 200)
        
        except Exception as e:
            return make_response(jsonify({"error": str(e)}), 500)
    
# class UpdateAdminIncidents(Resource):
#     def patch(self, id):
#         data = request.get_json()

#         incident = Admin.query.get(id)
#         action = data.get('action')

#         if incident:
#             incident.action = action
#             db.session.add(incident)
#             db.session.commit()
#             return make_response('Action updated!!')
        




api.add_resource(GetUser, '/user/<int:id>')
api.add_resource(Users, '/users')
api.add_resource(Signup, '/signup')
api.add_resource(Login, '/login')
api.add_resource(BanUser,'/users/<int:id>/ban')
api.add_resource(UnbanUser, '/users/<int:id>/unban')

# routes for incident
api.add_resource(Incident, '/incidents')
api.add_resource(GetIncidentId, '/gets-incident/<int:id>')
api.add_resource(UpdateIncident, '/updates-incident/<int:id>')
api.add_resource(DeleteIncident, '/deletes-incident/<int:id>')

# route for emergency
api.add_resource(EmergencyPost, '/emergency-reporting')

# routes for media
api.add_resource(MediaPost, '/media')
api.add_resource(MediaDelete, '/media/<int:id>')

# routes for admin actions
api.add_resource(AdminIncidents, '/admin/reports')
# api.add_resource(UpdateAdminIncidents, '/admin/status/<int:id>')
api.add_resource(UpdateIncidentStatus, '/incident/<int:id>/status')
api.add_resource(PostAdminIncidents, '/admin/status')

# routes for admin analytics
api.add_resource(Analytics, '/analytics')


# routes for notifications
# api.add_resource(GetNotifications, '/notifications')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5555))
    app.run(host="0.0.0.0", port=port, debug=True)