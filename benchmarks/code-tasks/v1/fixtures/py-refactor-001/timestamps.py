"""Public message stamps retain their message and numeric creation time."""
import time

def stamp(message):
    return {"message": message, "created_at": time.time()}
