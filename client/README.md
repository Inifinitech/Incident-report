
Accidents and emergencies are common occurrences in Kenya, and the key to saving lives often lies in how quickly first responders receive accurate information. "Ajali!" is a localized solution designed to facilitate the swift reporting and response to accidents or emergencies. Through this platform, any citizen can report accidents or emergencies, share important details, and ensure that the right authorities and the public are informed in real-time.

The goal of this project is to build an easy-to-use application that allows users to report incidents and track their status while providing vital information (such as geolocation, images, and videos) to support the claim. Administrators can also manage and update the status of incident reports.

----------

## Table of Contents

-   Built with
-   Project requirements and how to use it
    -   Frontend
    -   Backend
    -   Database
    -   Testing
    -   CI/CD Setup
    -   API Endpoints
-   Project Timeline
-   License

----------

## Built with

The project was developed using both frontend and backend technologies. The communication between the client and the server is handled via a REST API:

-   *Frontend*:
    
    -   ReactJS (UI)
    -   Redux Toolkit (State Management)
    -   SCSS for styling
    -   Google Maps API (For displaying incident locations)
-   *Backend*:
    
    -   Python (Flask)
    -   SQLite (Database)
    -   Flask Migrate (For database migrations)
    -   SQLAlchemy (ORM)
    -   Flask-RESTful (For building RESTful API endpoints)
-   *Testing*:
    
    -   Jest (Frontend testing)
    -   Pytest (Backend testing)
-   *CI/CD*:
    
    -   GitHub Actions (For automated deployment)
    -   CircleCI (For Continuous Integration)

----------

## Project Requirements and How to Use It

To run this project, both the frontend and backend environments need to be set up. Below are the steps for getting started with each part.

### Frontend

1.  Clone the repository:
    
    shell
    
    
    
    `$ git clone https://github.com/Inifinitech/Incident-report.git
    $ cd Incident-report 
    
2.  Navigate to the */frontend* directory and install the necessary dependencies:
    
    shell
    
    
    
    `$ cd server
    $ npm install` 
    
3.  Start the React application:
    
    shell
    
    
    
    $ npm run dev 
    
4.  Access the frontend application in your browser at:
    
    arduino
    
    
    
    http://localhost:3000 
    

### Backend

The backend environment can be set up using *Pipenv, which helps to manage Python dependencies and virtual environments. Below are the steps to use **Pipenv* for setting up your backend.

#### Using *Pipenv* for Backend Setup

1.  *Install Pipenv* (if you don't have it already):
    
    -   First, install *Pipenv* globally:
    
    shell
    
    
    
    $ pip install pipenv 
    
2.  *Install Dependencies*:
    
    -   Navigate to the */backend* directory where the Pipfile is located.
    
    shell
    
    
    
    $ cd server
    
    -   Install the necessary dependencies specified in the Pipfile:
    
    shell
    
    
    
    $ pipenv install --dev 
    
    -   This command will install both the development and production dependencies. It will also automatically create a virtual environment for your project.
3.  *Activate the Virtual Environment*:
    
    -   To activate the virtual environment created by *Pipenv*, use the following command:
    
    shell
    
    
    
    $ pipenv shell 
    
    -   This will activate the virtual environment and you will see the (venv) prompt indicating the virtual environment is active.
4.  *Run the Flask Application*:
    
    -   Now that the virtual environment is activated, you can run the Flask application:
    
    shell
    
    
    
    (venv) $ flask run 0r Python3 app.py
    
    -   You should see the Flask development server running on:
    
    csharp
    
    
    
    * Running on http://127.0.0.1:5000 
    

----------

### Database

The backend uses *SQLite* as the database. You don't need to set up any additional databases, as SQLite is serverless and stores data directly in a file.

1.  The database configuration is stored in the app/config.py file, and by default, it uses an SQLite database.
    
2.  The database file (app.db) will be created automatically when you run the migrations.
    
3.  Run migrations to set up the necessary database tables:
    
    shell
    
    
    
    (venv) $ flask db upgrade 
    

----------

### Testing

1.  *Frontend Testing (Jest)*:
    
    -   Run tests for the frontend application:
    
    shell
    
    
    
    $ npm run test 
    
2.  *Backend Testing (Pytest)*:
    
    -   Run tests for the backend application:
    
    shell
    
    
    
    (venv) $ pytest 
    

----------

### CI/CD Setup

GitHub Actions and CircleCI are used for continuous integration and deployment.

-   *GitHub Actions* is configured for automated testing and deployment. It runs automatically when code is pushed to the repository or a pull request is created.
    
-   *CircleCI* is used for the integration pipeline to ensure that the code is tested before deployment.
    

----------

## API Endpoints

The backend is designed with the following API endpoints:

HTTP Method

Resource URL

Description

POST

/api/auth/register

Register a new user

POST

/api/auth/login

User login

GET

/api/incidents

Get all incident reports

POST

/api/incidents

Create a new incident report

GET

/api/incidents/{id}

Get details of a single incident report

PUT

/api/incidents/{id}

Edit an existing incident report

DELETE

/api/incidents/{id}

Delete an incident report

PATCH

/api/incidents/{id}/geolocation

Add or update geolocation for the incident report

PATCH

/api/incidents/{id}/status

Admin change incident status (under investigation, resolved, etc.)

POST

/api/incidents/{id}/media

Add media (images/videos) to the incident report

The API returns responses in JSON format, with pagination implemented for fetching a large number of records.


----------

## License

This project is licensed under the MIT License - see the LICENSE file for details.