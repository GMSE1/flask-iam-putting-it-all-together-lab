#!/usr/bin/env python3

from flask import request, session
from flask_restful import Resource
from sqlalchemy.exc import IntegrityError

from config import app, db, api
from models import User, Recipe, UserSchema, RecipeSchema

class Signup(Resource):
    def post(self):
        data = request.get_json()
        
        try:
            # Create new user
            user = User(
                username=data.get('username'),
                image_url=data.get('image_url'),
                bio=data.get('bio')
            )
            # Set password (automatically hashed via setter)
            user.password_hash = data.get('password')
            
            # Save to database
            db.session.add(user)
            db.session.commit()
            
            # Log user in by setting session
            session['user_id'] = user.id
            
            # Return user object
            return UserSchema().dump(user), 201
            
        except IntegrityError:
            db.session.rollback()
            return {'error': 'Username already exists'}, 422
        except ValueError as e:
            db.session.rollback()
            return {'error': str(e)}, 422

class CheckSession(Resource):
    def get(self):
        # Check if user_id exists in session
        user_id = session.get('user_id')
        
        if user_id:
            # User is logged in - find and return user
            user = User.query.filter_by(id=user_id).first()
            return UserSchema().dump(user), 200
        
        # User is NOT logged in
        return {'error': 'Unauthorized'}, 401

class Login(Resource):
    def post(self):
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        # Find user by username
        user = User.query.filter_by(username=username).first()
        
        # Verify user exists and password is correct
        if user and user.authenticate(password):
            # Credentials are valid - log user in
            session['user_id'] = user.id
            return UserSchema().dump(user), 200
        
        # Invalid credentials
        return {'error': 'Unauthorized'}, 401

class Logout(Resource):
    def delete(self):
        # Check if user is logged in
        user_id = session.get('user_id')
        
        if user_id:
            # User is logged in - log them out
            session['user_id'] = None
            return {}, 204
        
        # User is NOT logged in
        return {'error': 'Unauthorized'}, 401

class RecipeIndex(Resource):
    def get(self):
        # Check if user is logged in
        if session.get('user_id'):
            # User is logged in - return all recipes
            recipes = Recipe.query.all()
            return [RecipeSchema().dump(recipe) for recipe in recipes], 200
        
        # User is NOT logged in
        return {'error': 'Unauthorized'}, 401
    
    def post(self):
        # Check if user is logged in
        if not session.get('user_id'):
            return {'error': 'Unauthorized'}, 401
        
        data = request.get_json()
        
        try:
            # Create new recipe belonging to logged-in user
            recipe = Recipe(
                title=data.get('title'),
                instructions=data.get('instructions'),
                minutes_to_complete=data.get('minutes_to_complete'),
                user_id=session['user_id']  # Associate with logged-in user
            )
            
            # Save to database
            db.session.add(recipe)
            db.session.commit()
            
            # Return recipe with nested user object
            return RecipeSchema().dump(recipe), 201
            
        except ValueError as e:
            # Validation error (e.g., instructions too short)
            db.session.rollback()
            return {'error': str(e)}, 422
        
api.add_resource(Signup, '/signup', endpoint='signup')
api.add_resource(CheckSession, '/check_session', endpoint='check_session')
api.add_resource(Login, '/login', endpoint='login')
api.add_resource(Logout, '/logout', endpoint='logout')
api.add_resource(RecipeIndex, '/recipes', endpoint='recipes')


if __name__ == '__main__':
    app.run(port=5555, debug=True)