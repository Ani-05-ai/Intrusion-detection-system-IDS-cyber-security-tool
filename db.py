import os
from pymongo import MongoClient

client = MongoClient(os.getenv("MONGO_URI", "mongodb://localhost:27017"))
db = client["ids_db"]

users_collection = db["users"]
alerts_collection = db["alerts"]