"""
Project: SentinAI NetGuard
Module: Authentication Service
Description: Manages user authentication, registration, and password updates.
License: MIT / Academic Use Only
"""
from datetime import datetime
from typing import Optional
from pymongo import MongoClient
from backend.core.database import db
from backend.core.config import config
from backend.core.security import verify_password, get_password_hash, create_access_token

class AuthService:
    """Service for handling User Authentication and Credentials."""
    
    def __init__(self):
        # We access the DB via the global db manager or directly if needed
        # In this architecture, db.get_db() returns the database instance
        self.collection_name = "users"

    def _get_collection(self):
        """Helper to get the users collection safely."""
        database = db.get_db()
        if database is not None:
            return database[self.collection_name]
        return None

    def authenticate_user(self, username, password):
        """
        Authenticates a user against the database.
        Returns access token if successful, None otherwise.
        """
        collection = self._get_collection()
        if collection is None:
            # Fallback for when DB is down? or just fail.
            # For simplicity, if DB is down, auth fails.
            # In a real scenario, implementing a fallback admin is risky but possible.
            print("[Auth] DB unavailable for authentication.")
            return None

        user = collection.find_one({"username": username})
        if not user:
            return None
        
        if not verify_password(password, user["hashed_password"]):
            return None
        
        return create_access_token(data={"sub": username, "role": user.get("role", "analyst")})

    def create_user(self, username, password, role="analyst"):
        """Creates a new user (Internal/Seed use)."""
        collection = self._get_collection()
        if collection is None: return False

        if collection.find_one({"username": username}):
            return False # User exists

        hashed_password = get_password_hash(password)
        collection.insert_one({
            "username": username,
            "hashed_password": hashed_password,
            "role": role,
            "created_at": datetime.now()
        })
        return True

    def change_password(self, username, old_password, new_password):
        """Updates the user's password."""
        collection = self._get_collection()
        if collection is None: return False

        user = collection.find_one({"username": username})
        if not user:
            return False

        if not verify_password(old_password, user["hashed_password"]):
            return False
        
        new_hash = get_password_hash(new_password)
        collection.update_one(
            {"username": username},
            {"$set": {"hashed_password": new_hash}}
        )
        return True

    def ensure_admin_user(self):
        """Ensures the default admin exists on startup."""
        from datetime import datetime
        collection = self._get_collection()
        if collection is not None:
            if not collection.find_one({"username": "admin"}):
                print("[Auth] Seeding default admin user...")
                self.create_user("admin", "admin", role="admin")

auth_service = AuthService()
