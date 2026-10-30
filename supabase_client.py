import os
from supabase import create_client, Client

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY = os.getenv("SUPABASE_KEY", "")

def get_supabase_client() -> Client:
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise ValueError("Supabase URL or Key missing in environment variables.")
    return create_client(SUPABASE_URL, SUPABASE_KEY)

def upsert_farmer_profile(phone: str, name: str, village: str) -> bool:
    """Saves or updates a farmer profile upon successful login."""
    try:
        supabase = get_supabase_client()
        data = {
            "phone": phone,
            "name": name,
            "village": village
        }
        # Upsert based on unique phone number
        supabase.table("farmers").upsert(data, on_conflict="phone").execute()
        return True
    except Exception as e:
        print("Supabase farmer profile upsert failed.")
        return False

def insert_sarpanch_feedback(village: str, sarpanch_id: str, verdict: str, khasra: str, observed_condition: str, notes: str) -> bool:
    """Inserts a Sarpanch weather verification log into Supabase."""
    try:
        supabase = get_supabase_client()
        data = {
            "village": village,
            "sarpanch_id": sarpanch_id,
            "verdict": verdict,
            "khasra": khasra,
            "observed_condition": observed_condition,
            "notes": notes
        }
        supabase.table("weather_feedback_log").insert(data).execute()
        return True
    except Exception as e:
        print("Supabase feedback insert failed.")
        return False

def fetch_feedback_for_village(village_name: str, limit: int = 5):
    """Fetches recent feedback records for a specific village."""
    try:
        supabase = get_supabase_client()
        response = supabase.table("weather_feedback_log") \
            .select("*") \
            .eq("village", village_name) \
            .order("timestamp", desc=True) \
            .limit(limit) \
            .execute()
        return response.data
    except Exception as e:
        print("Supabase feedback fetch failed.")
        return []