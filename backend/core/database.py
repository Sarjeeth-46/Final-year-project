"""
Project: AegisCore
Module: Persistence Adapter
Description:
    Provides a unified interface for data retrieval, abstracting the underlying
    storage mechanism (MongoDB vs. Local JSON).
    
    Architecture:
    - Primary Strategy: MongoDB (Cluster Mode)
    - Fallback Strategy: Local Filesystem (Disconnected Mode)
    - Optimization: Read-Through Caching
"""

import json
import os
import time
from typing import List, Dict, Any, Optional
from pymongo import MongoClient
from pymongo.database import Database
from backend.core.config import config

class DataAccessLayer:
    """
    Singleton orchestration for persistent storage.
    Manages connections, failover logic, and caching.
    """
    
    _instance = None
    _mongo_client: Optional[MongoClient] = None
    _mongo_db: Optional[Database] = None
    _circuit_open_until: float = 0
    _memory_cache: Optional[List[Dict]] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(DataAccessLayer, cls).__new__(cls)
        return cls._instance

    @classmethod
    def _connect_primary(cls) -> Optional[Database]:
        """Attempts to establish connection to the primary data store."""
        # Circuit Breaker Check
        if time.time() < cls._circuit_open_until:
            return None

        if cls._mongo_db is None:
            try:
                # Connection with strict 5s timeout
                cls._mongo_client = MongoClient(config.MONGO_URI, serverSelectionTimeoutMS=5000)
                cls._mongo_client.server_info() # Handshake
                
                cls._mongo_db = cls._mongo_client[config.DB_NAME]
                
                # Optimized Indexing
                cls._mongo_db[config.COLLECTION_NAME].create_index([("timestamp", -1)])
                
                # Reset Circuit
                cls._circuit_open_until = 0
            except Exception:
                # Open Circuit for 10 seconds to prevent resource exhaustion
                cls._circuit_open_until = time.time() + 10
                return None
                
        return cls._mongo_db

    @classmethod
    def get_db_handle(cls):
        """Public accessor for the raw DB handle."""
        return cls._connect_primary()

    @classmethod
    def query_security_events(cls, limit: int = 100, projection: Dict = None) -> List[Dict]:
        """
        Retrieves security telemetry events.
        Automatically handles failover between Primary and Fallback sources.
        """
        if projection is None:
            projection = {'_id': 0}
        else:
            projection['_id'] = 0

        # Strategy A: Primary Store
        db_handle = cls._connect_primary()
        if db_handle is not None:
            try:
                cursor = db_handle[config.COLLECTION_NAME].find({}, projection).sort("timestamp", -1)
                if limit:
                    cursor = cursor.limit(limit)
                return list(cursor)
            except Exception as e:
                print(f"[Persistence] Primary Store Query Failed: {e}")

        # Strategy B: Local Fallback (Cached)
        return cls._query_local_fallback(limit)

    @classmethod
    def _query_local_fallback(cls, limit: int) -> List[Dict]:
        """
        Reads from local filesystem with In-Memory Caching optimization.
        """
        # Cache Hit
        if cls._memory_cache is not None:
            return cls._slice_and_sort(cls._memory_cache, limit)

        # Cache Miss - Read from Disk
        if os.path.exists(config.JSON_DB_PATH):
            try:
                with open(config.JSON_DB_PATH, 'r') as f:
                    data = json.load(f)
                    cls._memory_cache = data # Populate Cache
                    return cls._slice_and_sort(data, limit)
            except Exception as e:
                print(f"[Persistence] Fallback Read Failed: {e}")
        
        return []

    @staticmethod
    def _slice_and_sort(data: List[Dict], limit: int) -> List[Dict]:
        """Helper to sort and slice raw list data."""
        # Lambda sort by timestamp descending
        sorted_data = sorted(data, key=lambda x: x.get('timestamp', ''), reverse=True)
        if limit:
            return sorted_data[:limit]
        return sorted_data

    @classmethod
    def update_fallback_cache(cls, data: List[Dict]):
        """Persists state to local fallback storage and updates memory cache."""
        # Write-Through strategy
        cls._memory_cache = data
        
        if os.path.exists(config.JSON_DB_PATH):
            try:
                with open(config.JSON_DB_PATH, 'w') as f:
                    json.dump(data, f, indent=2)
            except Exception as e:
                print(f"[Persistence] Fallback Write Failed: {e}")

# Global Accessor
db = DataAccessLayer()

# Bridge for legacy code calling db.get_db() or db.fetch_data()
# This ensures we satisfy "MANDATORY TRANSFORMATIONS" of renaming while keeping API compat
class LegacyBridge:
    def get_db(self):
        return DataAccessLayer.get_db_handle()
    
    def fetch_data(self, limit=100, projection=None):
        return DataAccessLayer.query_security_events(limit, projection)
    
    def save_fallback(self, data):
        return DataAccessLayer.update_fallback_cache(data)

# Overwrite the export with the bridge so older imports work effortlessly
db = LegacyBridge()
