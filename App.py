import os
import re
import csv
import time
import json
import base64
import html
import hmac
import hashlib
import textwrap
import logging
from datetime import datetime
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
from supabase_client import insert_sarpanch_feedback, fetch_feedback_for_village
from supabase_client import upsert_farmer_profile

# -----------------------------------------------------------------------------
# LOGGING SETUP (Prevents sensitive internal stack traces in UI)
# -----------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("SukshmaVrishti")

# -----------------------------------------------------------------------------
# AUTO-LOAD .ENV CONFIGURATION
# -----------------------------------------------------------------------------
def load_env_variables(env_path: str = ".env") -> None:
    """Safely loads key-value pairs from .env without executing shell commands."""
    if os.path.exists(env_path):
        try:
            with open(env_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, val = line.split("=", 1)
                        clean_key = key.strip()
                        clean_val = val.strip().strip('"').strip("'")
                        if re.match(r"^[A-Z0-9_]+$", clean_key):
                            os.environ[clean_key] = clean_val
        except Exception as exc:
            logger.warning("Failed to parse .env configuration.")

load_env_variables()

TWILIO_ACCOUNT_SID = os.getenv("TWILIO_ACCOUNT_SID", "")
TWILIO_AUTH_TOKEN = os.getenv("TWILIO_AUTH_TOKEN", "")
TWILIO_VERIFY_SERVICE_SID = os.getenv("TWILIO_VERIFY_SERVICE_SID", "")

# -----------------------------------------------------------------------------
# PAGE CONFIGURATION & SECURITY HEADERS SIMULATION
# -----------------------------------------------------------------------------
st.set_page_config(
    page_title="SUKSMAVRISHTI | सूक्ष्मवृष्टि",
    page_icon="🌾",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# -----------------------------------------------------------------------------
# CRYPTOGRAPHIC UTILITIES & RATE LIMITING
# -----------------------------------------------------------------------------
def hash_password(password: str, salt: str | None = None) -> str:
    """Create a PBKDF2-SHA256 password hash in salt_hex:digest_hex format.

    Use this helper only in a trusted administrative environment to provision
    SARPANCH_PASSWORD_HASH_* deployment secrets; never store plaintext passwords.
    """
    import secrets
    salt_bytes = bytes.fromhex(salt) if salt else secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, 600_000)
    return f"{salt_bytes.hex()}:{digest.hex()}"


def verify_password_hash(provided_password: str, stored_hash: str) -> bool:
    """Verify a salted PBKDF2 hash; fail closed for missing/legacy values."""
    if not stored_hash or ":" not in stored_hash:
        return False
    try:
        salt_hex, expected_hex = stored_hash.split(":", 1)
        salt_bytes = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(expected_hex)
        if len(salt_bytes) < 16 or len(expected) != 32:
            return False
        actual = hashlib.pbkdf2_hmac("sha256", provided_password.encode("utf-8"), salt_bytes, 600_000)
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False

def sanitize_csv_cell(value: str) -> str:
    """Prevents CSV / Formula Injection (CWE-1236) in exported or logged CSVs."""
    if not value:
        return ""
    val_str = str(value).strip().replace("\n", " ").replace("\r", " ")
    if val_str and val_str[0] in ("=", "+", "-", "@", "\t", "%"):
        return "'" + val_str
    return val_str

def is_rate_limited(action_key: str, max_attempts: int = 5, window_sec: int = 300) -> bool:
    """Protects authentication endpoints from brute-force attempts (CWE-307)."""
    now = time.time()
    tracker_key = f"_rate_{action_key}"
    if tracker_key not in st.session_state:
        st.session_state[tracker_key] = []
    
    # Filter attempts within the active time window
    attempts = [t for t in st.session_state[tracker_key] if now - t < window_sec]
    st.session_state[tracker_key] = attempts
    
    if len(attempts) >= max_attempts:
        return True
    
    st.session_state[tracker_key].append(now)
    return False

# -----------------------------------------------------------------------------
# HARDENED TEXT-TO-SPEECH (XSS IMMUNE)
# -----------------------------------------------------------------------------
def speak_page_text(text: str, language: str = "English") -> None:
    """
    Speaks page instructions via browser Web Speech API with strict input sanitization.
    """
    if not text or not text.strip():
        return

    lang_code = "hi-IN" if language in ("हिंदी", "hi") else "en-IN"
    # Whitelist characters to prevent script injection in DOM context
    sanitized = re.sub(r"[^a-zA-Z0-9\u0900-\u097F\s.,;:?!°/%()-]", "", text)
    sanitized = re.sub(r"\s+", " ", sanitized).strip()

    # json.dumps guarantees safe string encoding without unescaped delimiters
    js_code = f"""
    <script>
    (function() {{
        var speechText = {json.dumps(sanitized)};
        var langCode = "{html.escape(lang_code)}";

        function getTargetWindow() {{
            try {{
                if (window.parent && window.parent.speechSynthesis) return window.parent;
            }} catch(e) {{}}
            return window;
        }}

        var targetWin = getTargetWindow();
        if (!targetWin.speechSynthesis) return;

        targetWin.speechSynthesis.cancel();
        var utterance = new (targetWin.SpeechSynthesisUtterance || window.SpeechSynthesisUtterance)(speechText);
        utterance.lang = langCode;
        utterance.rate = 0.94;

        var voices = targetWin.speechSynthesis.getVoices() || [];
        var baseLang = langCode.split("-")[0];
        for (var i = 0; i < voices.length; i++) {{
            var vLang = (voices[i].lang || "").toLowerCase().replace("_", "-");
            if (vLang === langCode.toLowerCase()) {{
                utterance.voice = voices[i];
                break;
            }}
            if (vLang.indexOf(baseLang) === 0 && !utterance.voice) {{
                utterance.voice = voices[i];
            }}
        }}

        setTimeout(function() {{
            targetWin.speechSynthesis.speak(utterance);
        }}, 350);
    }})();
    </script>
    """
    components.html(js_code, height=0)

# -----------------------------------------------------------------------------
# TWILIO VERIFY OTP IMPLEMENTATION (SECURED & SANITIZED)
# -----------------------------------------------------------------------------
def format_to_e164(phone_number: str) -> str:
    """Validates and formats Indian numbers to strict E.164 (+91...)."""
    digits = re.sub(r"\D", "", phone_number)
    if digits.startswith("91") and len(digits) == 12:
        return f"+{digits}"
    if len(digits) == 10 and digits[0] in "6789":
        return f"+91{digits}"
    return ""

def send_twilio_verify_otp(phone_number: str) -> tuple[bool, str]:
    """Sends OTP using Twilio Verify with masked outputs and exception neutralization."""
    clean_phone = format_to_e164(phone_number)
    if not clean_phone:
        return False, "Invalid mobile number. Please enter a valid 10-digit number."

    if is_rate_limited("otp_send", max_attempts=4, window_sec=180):
        return False, "Too many requests. Please wait 3 minutes before requesting another OTP."

    if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_VERIFY_SERVICE_SID:
        try:
            from twilio.rest import Client
            client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
            verification = client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID) \
                .verifications \
                .create(to=clean_phone, channel="sms")
            masked = clean_phone[:3] + "XXXXXX" + clean_phone[-2:]
            return True, f"OTP sent to {masked} (Status: {verification.status})"
        except Exception as exc:
            logger.error("Twilio Verify request failed.")
            return False, "SMS gateway temporarily unavailable. Please try again shortly."
    else:
        logger.error("OTP provider is not configured; refusing demo verification fallback.")
        return False, "Phone verification is temporarily unavailable. Please try again later."

def check_twilio_verify_otp(phone_number: str, otp_code: str) -> tuple[bool, str]:
    """Validates OTP code with anti-brute-force rate limiting."""
    clean_phone = format_to_e164(phone_number)
    clean_code = re.sub(r"\D", "", str(otp_code)).strip()
    
    if len(clean_code) != 6:
        return False, "Please enter a valid 6-digit verification code."

    if is_rate_limited("otp_verify", max_attempts=5, window_sec=180):
        return False, "Too many failed attempts. Temporary lockout for 3 minutes."

    if TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_VERIFY_SERVICE_SID:
        try:
            from twilio.rest import Client
            client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
            verification_check = client.verify.v2.services(TWILIO_VERIFY_SERVICE_SID) \
                .verification_checks \
                .create(to=clean_phone, code=clean_code)
            if verification_check.status == "approved":
                return True, "Verification successful!"
            return False, "Incorrect verification code. Please check and try again."
        except Exception as exc:
            logger.error("Twilio Verify check failed.")
            return False, "Verification check failed. Please request a new code."
    else:
        logger.error("OTP provider is not configured; verification fails closed.")
        return False, "Phone verification is temporarily unavailable. Please try again later."

# -----------------------------------------------------------------------------
# IMAGE & LOGO HELPER (PATH TRAVERSAL PROOF)
# -----------------------------------------------------------------------------
def get_base64_image(image_path: str) -> str:
    """Reads project images while preventing arbitrary directory traversal."""
    safe_basename = os.path.basename(image_path)
    if os.path.exists(safe_basename):
        try:
            with open(safe_basename, "rb") as img_file:
                return base64.b64encode(img_file.read()).decode("utf-8")
        except Exception:
            return ""
    return ""

LOGO_FILE = "logo.png"
if not os.path.exists(LOGO_FILE):
    for candidate in os.listdir("."):
        if candidate.lower().endswith((".png", ".jpg", ".jpeg")) and "logo" in candidate.lower():
            LOGO_FILE = candidate
            break

# -----------------------------------------------------------------------------
# DATA LOADERS & SECURE CREDENTIAL REPOSITORY (HASHED PASSWORDS)
# -----------------------------------------------------------------------------
PREDICTIONS_CELL_CSV = "sukshmavrishti_64_cell_predictions.csv"
PREDICTIONS_KHASRA_CSV = "latest_khasra_weather_forecast.csv"
FEEDBACK_CSV = "weather_feedback_log.csv"

# Pre-hashed PBKDF2 credentials to prevent plaintext leakage in codebase
VILLAGE_LIST = [
    {"en": "Kalyani Basin", "hi": "कल्याणी कछार", "id": "sarpanch_kalyani", "hash": os.getenv("SARPANCH_PASSWORD_HASH_KALYANI", "")},
    {"en": "Deokhaliya", "hi": "देवखलिया", "id": "sarpanch_deokhaliya", "hash": os.getenv("SARPANCH_PASSWORD_HASH_DEOKHALIYA", "")},
    {"en": "Masauli", "hi": "मसौली", "id": "sarpanch_masauli", "hash": os.getenv("SARPANCH_PASSWORD_HASH_MASAULI", "")},
    {"en": "Chhatauni", "hi": "छतौनी", "id": "sarpanch_chhatauni", "hash": os.getenv("SARPANCH_PASSWORD_HASH_CHHATAUNI", "")},
    {"en": "Rasauli", "hi": "रसौली", "id": "sarpanch_rasauli", "hash": os.getenv("SARPANCH_PASSWORD_HASH_RASAULI", "")},
    {"en": "Satrikh", "hi": "सतरिख", "id": "sarpanch_satrikh", "hash": os.getenv("SARPANCH_PASSWORD_HASH_SATRIKH", "")},
    {"en": "Rampur", "hi": "रामपुर", "id": "sarpanch_rampur", "hash": os.getenv("SARPANCH_PASSWORD_HASH_RAMPUR", "")},
    {"en": "Fatehpur", "hi": "फतेहपुर", "id": "sarpanch_fatehpur", "hash": os.getenv("SARPANCH_PASSWORD_HASH_FATEHPUR", "")},
    {"en": "Safedabad", "hi": "सफेदाबाद", "id": "sarpanch_safedabad", "hash": os.getenv("SARPANCH_PASSWORD_HASH_SAFEDABAD", "")},
    {"en": "Nawabganj", "hi": "नवाबगंज", "id": "sarpanch_nawabganj", "hash": os.getenv("SARPANCH_PASSWORD_HASH_NAWABGANJ", "")},
    {"en": "Bado Sarai", "hi": "बदो सरायं", "id": "sarpanch_badosarai", "hash": os.getenv("SARPANCH_PASSWORD_HASH_BADOSARAI", "")},
    {"en": "Zaidpur", "hi": "जैदपुर", "id": "sarpanch_zaidpur", "hash": os.getenv("SARPANCH_PASSWORD_HASH_ZAIDPUR", "")},
]

def fetch_prediction_for_khasra(khasra_no: str, village_filter: str = None) -> dict:
    """Safely searches cadastral tables with parameterized string lookups."""
    q = str(khasra_no).strip().lower()

    if os.path.exists(PREDICTIONS_KHASRA_CSV):
        try:
            df_k = pd.read_csv(PREDICTIONS_KHASRA_CSV)
            m = df_k[df_k["khasra_gata_number"].astype(str).str.strip().str.lower() == q]
            if not m.empty:
                r = m.iloc[0]
                return {
                    "cell_id": str(r.get("cell_id", "cell_0_0")),
                    "village_en": str(r.get("village_mauza_en", "Kalyani Basin")),
                    "village_hi": str(r.get("village_mauza_hi", "कल्याणी कछार")),
                    "holder": str(r.get("landholder_name_hi", r.get("landholder_name_en", "खातेदार"))),
                    "crop": str(r.get("primary_crop", "Wheat (गेहूं)")),
                    "khasras": str(r.get("khasra_gata_number", khasra_no)),
                    "elevation": float(r.get("elevation_m", 117.33)),
                    "twi": float(r.get("twi", 11.06)),
                    "rain_mm": float(r.get("pred_downscaled_rain_mm", 35.81)),
                    "wind_kmh": float(r.get("pred_downscaled_wind_kmh", 12.04)),
                    "waterlog_risk": int(r.get("pred_waterlogging_risk", 0)),
                    "status_en": str(r.get("advisory_status_en", "NORMAL")),
                    "advisory_hi": str(r.get("cadastral_advisory_hi", "")),
                    "advisory_en": str(r.get("cadastral_advisory_en", "")),
                }
        except Exception as exc:
            logger.error("Could not read Khasra forecast data.")

    if os.path.exists(PREDICTIONS_CELL_CSV):
        try:
            df_c = pd.read_csv(PREDICTIONS_CELL_CSV)
            for _, row in df_c.iterrows():
                samples = [s.strip().lower() for s in str(row.get("sample_khasra_numbers", "")).split(",")]
                if q in samples or q in str(row.get("sample_khasra_numbers", "")).lower():
                    return {
                        "cell_id": str(row.get("cell_id", "cell_0_0")),
                        "village_en": str(row.get("village_mauza_en", "Kalyani Basin")),
                        "village_hi": str(row.get("village_mauza_hi", "कल्याणी कछार")),
                        "holder": "पंजीकृत खातेदार",
                        "crop": str(row.get("dominant_crop", "Wheat (गेहूं)")),
                        "khasras": str(row.get("sample_khasra_numbers", khasra_no)),
                        "elevation": float(row.get("elevation_m", 117.33)),
                        "twi": float(row.get("twi", 11.06)),
                        "rain_mm": float(row.get("pred_downscaled_rain_mm", 35.81)),
                        "wind_kmh": float(row.get("pred_downscaled_wind_kmh", 12.04)),
                        "waterlog_risk": int(row.get("pred_waterlogging_risk", 0)),
                        "status_en": str(row.get("advisory_status_en", "NORMAL")),
                        "advisory_hi": str(row.get("cadastral_advisory_hi", "")),
                        "advisory_en": str(row.get("cadastral_advisory_en", "")),
                    }
        except Exception as exc:
            logger.error("Could not read cell forecast data.")

    # Fallback default
    return {
        "cell_id": "cell_0_0",
        "village_en": "Kalyani Basin",
        "village_hi": "कल्याणी कछार",
        "holder": "पंजीकृत खातेदार",
        "crop": "Wheat (गेहूं)",
        "khasras": str(khasra_no),
        "elevation": 117.33,
        "twi": 11.06,
        "rain_mm": 35.81,
        "wind_kmh": 12.04,
        "waterlog_risk": 0,
        "status_en": "CRITICAL: High Waterlogging Risk",
        "advisory_hi": f"गाटा संख्या ({html.escape(str(khasra_no))}) के लिए चेतावनी: TWI अधिक होने से खेत में जलभराव की संभावना है। • सिंचाई परामर्श: सिंचाई तत्काल पूर्णतः बंद रखें। • परिवहन परामर्श: कच्ची पटरियों पर फिसलन है, अनाज ढककर सुरक्षित ले जाएं।",
        "advisory_en": f"Warning for Gata ({html.escape(str(khasra_no))}): High TWI indicates waterlogging risk. • Irrigation Action: Halt canal and tube-well irrigation immediately. • Transport Action: Avoid open trolley transit on unpaved roads.",
    }

# -----------------------------------------------------------------------------
# SESSION STATE INITIALIZATION & TAMPER RESISTANCE
# -----------------------------------------------------------------------------
DEFAULT_STATES = {
    "splash_done": False,
    "lang_chosen": False,
    "language": "English",
    "role": None,
    "farmer_logged_in": False,
    "farmer_profile": {},
    "sarpanch_logged_in": False,
    "sarpanch_profile": {},
    "otp_sent": False,
    "otp_phone": "",
    "current_page": "welcome"
}

for state_key, default_val in DEFAULT_STATES.items():
    if state_key not in st.session_state:
        st.session_state[state_key] = default_val

# -----------------------------------------------------------------------------
# 1. SPLASH SCREEN (5 SECONDS)
# -----------------------------------------------------------------------------
if not st.session_state.splash_done:
    splash_placeholder = st.empty()
    logo_base64 = get_base64_image(LOGO_FILE)
    img_html = f'<div class="logo-circle-container"><img src="data:image/png;base64,{logo_base64}" class="splash-logo-circle" alt="Logo"></div>' if logo_base64 else '<div class="splash-icon">🌾</div>'

    with splash_placeholder.container():
        splash_html = f"""
<style>
.splash-wrapper {{
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    min-height: 82vh; text-align: center; animation: fadeIn 0.8s ease-in-out;
}}
.logo-circle-container {{
    width: 240px; height: 240px; border-radius: 50%; overflow: hidden;
    display: flex; align-items: center; justify-content: center;
    border: 4px solid #2e7d32; box-shadow: 0 0 35px rgba(46, 125, 50, 0.45);
    margin: 0 auto 25px auto; background-color: #04141f;
}}
.splash-logo-circle {{ width: 100%; height: 100%; object-fit: cover; }}
.splash-icon {{ font-size: 110px; margin-bottom: 20px; }}
.splash-title {{
    font-size: 3.4rem; font-weight: 900; letter-spacing: 5px; color: #4ade80 !important;
    text-shadow: 0 2px 14px rgba(74, 222, 128, 0.35); text-transform: uppercase;
}}
.splash-slogan-hindi {{
    font-size: 1.85rem; font-weight: 700; color: #facc15 !important;
    letter-spacing: 1.5px; margin-bottom: 25px;
}}
.splash-loader {{
    width: 240px; height: 6px; background-color: rgba(255, 255, 255, 0.15);
    border-radius: 4px; overflow: hidden; margin-top: 10px;
}}
.splash-loader-bar {{
    width: 100%; height: 100%; background: linear-gradient(90deg, #4ade80, #facc15);
    animation: loadProgress 5s linear forwards;
}}
@keyframes loadProgress {{ from {{ width: 0%; }} to {{ width: 100%; }} }}
@keyframes fadeIn {{ from {{ opacity: 0; }} to {{ opacity: 1; }} }}
</style>
<div class="splash-wrapper">
    {img_html}
    <div class="splash-title">SUKSMAVRISHTI</div>
    <div class="splash-slogan-hindi">सर्वप्रयत्नेन धान्यसंरक्षणम्</div>
    <div class="splash-loader"><div class="splash-loader-bar"></div></div>
</div>
"""
        st.markdown(textwrap.dedent(splash_html), unsafe_allow_html=True)
        speak_page_text("सूक्ष्मवृष्टि में आपका स्वागत है। सर्वप्रयत्नेन धान्यसंरक्षणम्। Welcome to Suksmavrishti.", "hi")
        time.sleep(5)
        st.session_state.splash_done = True
        splash_placeholder.empty()
        st.rerun()

# -----------------------------------------------------------------------------
# 2. LANGUAGE SELECTION SCREEN
# -----------------------------------------------------------------------------
elif not st.session_state.lang_chosen:
    lang_html = """
<div style="text-align: center; margin-top: 50px;">
    <h1 style="color: #4ade80; font-size: 2.8rem; font-weight: 900; letter-spacing: 2px;">SUKSMAVRISHTI | सूक्ष्मवृष्टि</h1>
    <h3 style="color: #facc15; margin-bottom: 30px;">Choose Your Preferred Language / अपनी भाषा चुनें</h3>
</div>
"""
    st.markdown(textwrap.dedent(lang_html), unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns([1.2, 1, 1, 1.2])
    with col2:
        if st.button("🇬🇧 English", use_container_width=True, type="primary"):
            st.session_state.language = "English"
            st.session_state.lang_chosen = True
            st.rerun()
    with col3:
        if st.button("🇮🇳 हिंदी", use_container_width=True, type="primary"):
            st.session_state.language = "हिंदी"
            st.session_state.lang_chosen = True
            st.rerun()

    speak_page_text("Welcome to Suksmavrishti. Please choose your language. सूक्ष्मवृष्टि में आपका स्वागत है। कृपया अपनी भाषा चुनें।", "en")

# -----------------------------------------------------------------------------
# 3. ROLE SELECTION SCREEN (FARMER vs SARPANCH)
# -----------------------------------------------------------------------------
elif st.session_state.role is None:
    is_hi = (st.session_state.language == "हिंदी")
    title_text = "पैनल चयन करें" if is_hi else "Select Access Role"
    sub_text = "कृपया अपनी भूमिका का चयन करें" if is_hi else "Please choose who you are logging in as"
    farmer_lbl = "👨‍🌾 किसान लॉगिन (Farmer Login)" if is_hi else "👨‍🌾 Login as Farmer"
    sarpanch_lbl = "🛡️ सरपंच लॉगिन (Sarpanch Login)" if is_hi else "🛡️ Login as Sarpanch"

    role_html = f"""
<div style="text-align: center; margin-top: 50px; margin-bottom: 30px;">
    <h1 style="color: #4ade80; font-size: 2.6rem; font-weight: 900;">{html.escape(title_text)}</h1>
    <p style="color: #cbd5e1; font-size: 1.15rem;">{html.escape(sub_text)}</p>
</div>
"""
    st.markdown(textwrap.dedent(role_html), unsafe_allow_html=True)
    col1, col2, col3, col4 = st.columns([1.2, 1.4, 1.4, 1.2])
    with col2:
        if st.button(farmer_lbl, use_container_width=True, type="primary"):
            st.session_state.role = "farmer"
            st.session_state.current_page = "welcome"
            st.rerun()
    with col3:
        if st.button(sarpanch_lbl, use_container_width=True, type="primary"):
            st.session_state.role = "sarpanch"
            st.session_state.current_page = "sarpanch_login"
            st.rerun()

    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)
    b_col1, b_col2, b_col3 = st.columns([2, 1, 2])
    with b_col2:
        if st.button("🌐 " + ("भाषा बदलें" if is_hi else "Change Language"), use_container_width=True):
            st.session_state.lang_chosen = False
            st.rerun()

    role_speech = (
        "अब अपनी भूमिका चुनें। यदि आप किसान हैं तो किसान लॉगिन दबाएं, या यदि आप सरपंच हैं तो सरपंच लॉगिन चुनें।"
        if is_hi else
        "Now choose who you are. Press Login as Farmer if you are a farmer, or Login as Sarpanch if you are the village chief."
    )
    speak_page_text(role_speech, st.session_state.language)

# -----------------------------------------------------------------------------
# 4. FARMER: WELCOME PAGE (WITH UPPER-LEFT LOGIN BUTTON)
# -----------------------------------------------------------------------------
elif st.session_state.role == "farmer" and st.session_state.current_page == "welcome":
    is_hi = (st.session_state.language == "हिंदी")

    nav_left, nav_mid, nav_right = st.columns([3.5, 4.5, 2])
    with nav_left:
        if not st.session_state.farmer_logged_in:
            login_btn_label = "🔐 किसान लॉगिन (Farmer Login)" if is_hi else "🔐 Farmer Login"
            if st.button(login_btn_label, type="primary"):
                st.session_state.current_page = "farmer_login"
                st.rerun()
        else:
            p_name = html.escape(st.session_state.farmer_profile.get("name", "Farmer"))
            st.success(f"👤 {p_name} (Logged In)")
            if st.button("🚪 Logout", key="farmer_logout"):
                st.session_state.farmer_logged_in = False
                st.session_state.farmer_profile = {}
                st.session_state.otp_sent = False
                st.rerun()

    with nav_right:
        if st.button("🔄 " + ("भूमिका बदलें" if is_hi else "Switch Role")):
            st.session_state.role = None
            st.rerun()

    st.markdown("<hr style='margin: 8px 0 20px 0; border: none; height: 1px; background-color: rgba(255,255,255,0.15);'/>", unsafe_allow_html=True)

    col_w1, col_w2 = st.columns([3.8, 6.2])
    with col_w1:
        logo_base64 = get_base64_image(LOGO_FILE)
        if logo_base64:
            logo_html = f"""
<div style="display: flex; justify-content: center; align-items: center; padding: 15px;">
    <div style="width: 260px; height: 260px; border-radius: 50%; overflow: hidden; border: 4px solid #4ade80; box-shadow: 0 10px 30px rgba(0,0,0,0.45);">
        <img src="data:image/png;base64,{logo_base64}" style="width: 100%; height: 100%; object-fit: cover;" alt="Logo" />
    </div>
</div>
"""
            st.markdown(textwrap.dedent(logo_html), unsafe_allow_html=True)
        else:
            st.info("🌾 SūkṣmaVṛṣṭi Agromet System")

    with col_w2:
        if not is_hi:
            welcome_text = """
<div style="color: #f8fafc;">
    <h1 style="color: #4ade80; font-size: 2.6rem; font-weight: 800; margin-bottom: 6px;">
        Welcome to Suksmavrishti
    </h1>
    <div style="display: flex; align-items: baseline; flex-wrap: wrap; gap: 8px; margin-top: 4px; margin-bottom: 12px;">
        <span style="color: #facc15; font-size: 1.45rem; font-weight: 800;">
            "सर्वप्रयत्नेन धान्यसंरक्षणम्"
        </span>
        <span style="color: #cbd5e1; font-size: 1.15rem; font-weight: 500; font-style: italic;">
            — Protecting Every Grain with Precision
        </span>
    </div>
    <p style="font-size: 1.15rem; line-height: 1.7; color: #e2e8f0; margin-top: 14px;">
        <strong style="color: #67e8f9;">Suksmavrishti</strong> provides 1 km × 1 km hyperlocal 
        weather downscaling, irrigation management, and transit advisories for Barabanki, Uttar Pradesh.
    </p>
    <div style="background: rgba(30, 41, 59, 0.7); padding: 18px 22px; border-radius: 12px; border-left: 5px solid #4ade80; margin: 18px 0;">
        <h4 style="color: #facc15; margin-top: 0; margin-bottom: 10px;">Key Capabilities:</h4>
        <ul style="font-size: 1.05rem; line-height: 1.8; color: #f1f5f9; margin-bottom: 0;">
            <li><b style="color: #38bdf8;">1 km × 1 km Micro-Precision:</b> Downscaled rain, wind, and convective alerts via machine learning.</li>
            <li><b style="color: #38bdf8;">Irrigation & Drainage Management:</b> Actionable directives to halt tube-wells or utilize precipitation efficiently.</li>
            <li><b style="color: #38bdf8;">Transport & Mandi Protection:</b> Transit alerts to protect harvested produce during road haulage.</li>
        </ul>
    </div>
</div>
"""
            btn_label = "📍 View Weather Forecast"
        else:
            welcome_text = """
<div style="color: #f8fafc;">
    <h1 style="color: #4ade80; font-size: 2.6rem; font-weight: 800; margin-bottom: 6px;">
        सूक्ष्मवृष्टि में आपका स्वागत है
    </h1>
    <div style="display: flex; align-items: baseline; flex-wrap: wrap; gap: 8px; margin-top: 4px; margin-bottom: 12px;">
        <span style="color: #facc15; font-size: 1.45rem; font-weight: 800;">
            "सर्वप्रयत्नेन धान्यसंरक्षणम्"
        </span>
        <span style="color: #cbd5e1; font-size: 1.15rem; font-weight: 500; font-style: italic;">
            — हर दाने की सुरक्षा, सूक्ष्म सटीकता के साथ
        </span>
    </div>
    <p style="font-size: 1.15rem; line-height: 1.7; color: #e2e8f0; margin-top: 14px;">
        <strong style="color: #67e8f9;">सूक्ष्मवृष्टि (Suksmavrishti)</strong> उत्तर प्रदेश के बाराबंकी जनपद 
        हेतु 1 किमी × 1 किमी रिज़ॉल्यूशन पर आधारित एक अत्याधुनिक हाइपरलोकल मौसम, सिंचाई और परिवहन परामर्श प्रणाली है।
    </p>
    <div style="background: rgba(30, 41, 59, 0.7); padding: 18px 22px; border-radius: 12px; border-left: 5px solid #4ade80; margin: 18px 0;">
        <h4 style="color: #facc15; margin-top: 0; margin-bottom: 10px;">प्रमुख विशेषताएं:</h4>
        <ul style="font-size: 1.05rem; line-height: 1.8; color: #f1f5f9; margin-bottom: 0;">
            <li><b style="color: #38bdf8;">1 किमी × 1 किमी सूक्ष्म सटीकता:</b> मशीन लर्निंग द्वारा गांव व खेत स्तर पर बारिश व आंधी की सटीक चेतावनी।</li>
            <li><b style="color: #38bdf8;">सिंचाई व जल निकासी परामर्श:</b> नलकूप नियंत्रण, जलभराव निवारण और वर्षा जल सदुपयोग निर्देश।</li>
            <li><b style="color: #38bdf8;">परिवहन व मंडी सुरक्षा:</b> कटी फसल परिवहन, ट्रॉली आच्छादन और सुगम आवागमन चेतावनी।</li>
        </ul>
    </div>
</div>
"""
            btn_label = "📍 मौसम का पूर्वानुमान देखें"

        st.markdown(textwrap.dedent(welcome_text), unsafe_allow_html=True)
        st.markdown("<div style='margin-top: 20px;'></div>", unsafe_allow_html=True)
        if st.button(btn_label, type="primary", use_container_width=True):
            if not st.session_state.farmer_logged_in:
                st.info("कृपया मौसम पूर्वानुमान देखने से पहले ऊपर बाएँ कोने से लॉगिन करें।" if is_hi else "Please login first using the top-left button to view the forecast.")
                st.session_state.current_page = "farmer_login"
                st.rerun()
            else:
                st.session_state.current_page = "forecast"
                st.rerun()

    welcome_speech = (
        "नमस्कार! सूक्ष्मवृष्टि में आपका स्वागत है। बाराबंकी जनपद हेतु एक किलोमीटर सूक्ष्म सटीक मौसम पूर्वानुमान, सिंचाई और परिवहन सलाह। कृपया लॉगिन करें या सीधे मौसम का पूर्वानुमान देखें।"
        if is_hi else
        "Welcome to Suksmavrishti. Hyperlocal weather forecasting, irrigation, and transport advisories for Barabanki. Please login or view weather forecast to proceed."
    )
    speak_page_text(welcome_speech, st.session_state.language)

# -----------------------------------------------------------------------------
# 5. FARMER LOGIN SCREEN (NAME, PHONE, VILLAGE & TWILIO VERIFY OTP)
# -----------------------------------------------------------------------------
elif st.session_state.role == "farmer" and st.session_state.current_page == "farmer_login":
    is_hi = (st.session_state.language == "हिंदी")

    b_col, _ = st.columns([3, 7])
    with b_col:
        if st.button("⬅️ " + ("वापस मुख्य पृष्ठ" if is_hi else "Back to Welcome")):
            st.session_state.current_page = "welcome"
            st.rerun()

    login_head_html = f"""
<div style="margin-top: 10px; margin-bottom: 25px;">
    <h2 style="color: #4ade80;">🔐 {'किसान लॉगिन एवं OTP सत्यापन' if is_hi else 'Farmer Login & OTP Verification'}</h2>
    <p style="color: #cbd5e1;">{'अपना नाम, 10 अंकों का मोबाइल नंबर और गांव दर्ज कर Twilio OTP प्राप्त करें।' if is_hi else 'Enter your Name, 10-digit Mobile Number, and Village to receive a Twilio Verify SMS code.'}</p>
</div>
"""
    st.markdown(textwrap.dedent(login_head_html), unsafe_allow_html=True)

    if not st.session_state.otp_sent:
        with st.form("farmer_reg_form"):
            name_input = st.text_input("किसान का नाम (Farmer's Name)" if is_hi else "Farmer Name", placeholder="e.g. Ram Kumar")
            phone_input = st.text_input("मोबाइल नंबर (10-digit Mobile Number)" if is_hi else "Mobile Number", placeholder="e.g. 9876543210")
            
            village_names = [v["hi"] if is_hi else v["en"] for v in VILLAGE_LIST]
            village_input = st.selectbox("गांव / मौजा का नाम (Village Name)" if is_hi else "Village / Mauza", options=village_names)
            
            submit_reg = st.form_submit_button("📨 OTP प्राप्त करें (Send OTP)" if is_hi else "📨 Send OTP", type="primary")

        if submit_reg:
            # Strict regex validation on input parameters (CWE-20)
            clean_name = re.sub(r"[^a-zA-Z\u0900-\u097F\s.]", "", name_input).strip()
            clean_phone = format_to_e164(phone_input)

            if not clean_name or len(clean_name) < 2:
                st.error("कृपया अपना मान्य नाम दर्ज करें।" if is_hi else "Please enter a valid name (at least 2 letters).")
            elif not clean_phone:
                st.error("कृपया एक मान्य 10 अंकों का भारतीय मोबाइल नंबर दर्ज करें (6-9 से शुरू)।" if is_hi else "Please enter a valid 10-digit Indian mobile number.")
            else:
                success, msg = send_twilio_verify_otp(clean_phone)
                if success:
                    st.session_state.otp_sent = True
                    st.session_state.otp_phone = clean_phone
                    st.session_state.farmer_profile = {
                        "name": clean_name,
                        "phone": clean_phone,
                        "village": village_input
                    }
                    st.success(msg)
                    st.rerun()
                else:
                    st.error(msg)

        f_speech = (
            "किसान लॉगिन पृष्ठ। कृपया अपना नाम, दस अंकों का मोबाइल नंबर और अपने गांव का नाम दर्ज करें और ओ टी पी प्राप्त करें बटन दबाएं।"
            if is_hi else
            "Farmer login page. Please enter your name, 10-digit mobile number, and village name, then press Send OTP."
        )
        speak_page_text(f_speech, st.session_state.language)

    else:
        masked_phone = st.session_state.otp_phone[:3] + "XXXXXX" + st.session_state.otp_phone[-2:]
        st.info(f"{'सत्यापन कोड (OTP) भेजा गया है:' if is_hi else 'Verification OTP sent to:'} {masked_phone}")
        otp_code = st.text_input("6-अंकीय OTP कोड दर्ज करें (Enter 6-digit OTP)" if is_hi else "Enter 6-digit OTP Code", max_chars=6)

        v_col1, v_col2 = st.columns([2, 2])
        with v_col1:
            if st.button("✅ OTP सत्यापित करें (Verify & Login)" if is_hi else "✅ Verify & Login", type="primary"):
                valid, v_msg = check_twilio_verify_otp(st.session_state.otp_phone, otp_code)
                if valid:
                    st.session_state.farmer_logged_in = True
                    st.session_state.otp_sent = False
                    st.session_state.current_page = "forecast"
                    st.success(v_msg)
                    st.rerun()
                else:
                    st.error(v_msg)
        with v_col2:
            if st.button("🔄 पुनः OTP भेजें (Resend OTP)" if is_hi else "🔄 Resend OTP"):
                send_twilio_verify_otp(st.session_state.otp_phone)
                st.info("OTP पुनः प्रेषित किया गया।" if is_hi else "OTP resent.")

        otp_speech = (
            f"आपके मोबाइल नंबर पर छह अंकों का ओ टी पी भेजा गया है। कृपया ओ टी पी दर्ज करके सत्यापित करें।"
            if is_hi else
            f"A 6-digit OTP has been sent to your mobile phone. Please enter the OTP code and verify."
        )
        speak_page_text(otp_speech, st.session_state.language)

# -----------------------------------------------------------------------------
# 6. WEATHER FORECAST & ADVISORY (XSS SANITIZED & FORMATTED)
# -----------------------------------------------------------------------------
elif st.session_state.current_page == "forecast":
    is_hi = (st.session_state.language == "हिंदी")

    back_col, _, role_ind = st.columns([3, 4, 3])
    with back_col:
        back_dest = "chief_home" if st.session_state.role == "sarpanch" else "welcome"
        if st.button("⬅️ " + ("वापस जाएं" if is_hi else "Back")):
            st.session_state.current_page = back_dest
            st.rerun()
    with role_ind:
        if st.session_state.role == "sarpanch":
            s_name = html.escape(st.session_state.sarpanch_profile.get("village", "Barabanki"))
            st.caption(f"🛡️ Sarpanch: {s_name}")
        else:
            f_name = html.escape(st.session_state.farmer_profile.get("name", "Registered"))
            st.caption(f"👨‍🌾 Farmer: {f_name}")

    title_text = "🌾 खसरा वार मौसम पूर्वानुमान एवं कृषि/परिवहन परामर्श" if is_hi else "🌾 Plot-Level Weather, Irrigation & Transport Advisory"
    sub_text = "अपने खेत का खसरा नंबर दर्ज करें और तत्काल 1 किमी x 1 किमी सटीक मौसम, सिंचाई व परिवहन सलाह प्राप्त करें।" if is_hi else "Enter your Khasra Number to get instant 1 km x 1 km downscaled weather, irrigation, and transport directives."

    st.markdown(f"<h2 style='color: #4ade80; margin-bottom: 2px;'>{html.escape(title_text)}</h2>", unsafe_allow_html=True)
    st.markdown(f"<p style='color: #cbd5e1; font-size: 1.05rem; margin-bottom: 22px;'>{html.escape(sub_text)}</p>", unsafe_allow_html=True)

    f_col1, f_col2 = st.columns([5, 5])
    with f_col1:
        khasra_label = "खसरा / गाटा नंबर दर्ज करें (Enter Khasra Number)" if is_hi else "Enter Khasra Number (खसरा नंबर)"
        khasra_input = st.text_input(
            label=khasra_label,
            value="",
            placeholder="e.g. 21, 21क, 50, 86, 114",
            help="Type your cadastral Khasra / Gata number",
            max_chars=20
        )

    with f_col2:
        village_filter_label = "गांव / मौजा चुनें" if is_hi else "Select Village / Mauza"
        village_opts = [v["hi"] if is_hi else v["en"] for v in VILLAGE_LIST]
        selected_village_choice = st.selectbox(village_filter_label, options=village_opts, index=0)

    btn_tell_label = "🌤️ मौसम का पूर्वानुमान बताएं (Tell Weather Forecast)" if is_hi else "🌤️ Tell Weather Forecast"
    tell_clicked = st.button(btn_tell_label, type="primary")

    if tell_clicked:
        # Whitelist Khasra input against injection (CWE-20)
        clean_input = re.sub(r"[^0-9a-zA-Z\u0900-\u097F\s/\-.,]", "", khasra_input).strip()
        if not clean_input:
            st.warning("कृपया एक मान्य खसरा नंबर दर्ज करें।" if is_hi else "Please enter a valid Khasra Number.")
            speak_page_text("कृपया एक मान्य खसरा नंबर दर्ज करें।" if is_hi else "Please enter a valid Khasra number.", st.session_state.language)
        else:
            pred = fetch_prediction_for_khasra(clean_input, selected_village_choice)
            v_name = pred["village_hi"] if is_hi else pred["village_en"]

            is_critical = pred["waterlog_risk"] == 1 or "CRITICAL" in pred["status_en"] or pred["rain_mm"] >= 35.0
            is_moderate = pred["rain_mm"] >= 10.0 and not is_critical

            if is_critical:
                badge_lbl = "🚨 RED ALERT / अत्यधिक जलभराव एवं परिवहन जोखिम"
                box_bg = "rgba(239, 68, 68, 0.15)"
                box_border = "#ef4444"
                text_col = "#fca5a5"
                irrigation_directive = (
                    "नलकूप व नहर से सिंचाई तत्काल पूर्णतः बंद रखें। ढलान की ओर खेत की मेड़ काटकर जल निकासी नालियां खोलें ताकि जड़ गलन न हो।"
                    if is_hi else
                    "Halt all tube-well and canal irrigation immediately. Unclog drainage channels along downhill slope to prevent root asphyxiation."
                )
                transport_directive = (
                    "कच्चे संपर्क मार्गों पर जलभराव व फिसलन का गंभीर जोखिम है। खुली ट्रैक्टर-ट्रॉलियों में अनाज ढुलाई न करें; कटी फसल तिरपाल से ढकें।"
                    if is_hi else
                    "Severe waterlogging on rural dirt tracks. Avoid transit of harvested produce in open tractor-trolleys; lash waterproof tarpaulins."
                )
            elif is_moderate:
                badge_lbl = "⚠️ AMBER ADVISORY / मौसम चेतावनी - सिंचाई स्थगन"
                box_bg = "rgba(245, 158, 11, 0.15)"
                box_border = "#f59e0b"
                text_col = "#fde68a"
                irrigation_directive = (
                    "आगामी 36 से 48 घंटों तक सिंचाई स्थगित रखें और वर्षा जल का उपयोग करें। रासायनिक उर्वरक का बुरकाव टालें।"
                    if is_hi else
                    "Postpone scheduled irrigation for 36-48 hours and utilize rainfall. Defer granular urea and fertilizer top-dressing."
                )
                transport_directive = (
                    "मंडी जाने वाली उपज की बोरियों को वाटरप्रूफ तिरपाल से अच्छी तरह ढकें; गीली सड़कों पर सुरक्षित गति से वाहन चलाएं।"
                    if is_hi else
                    "Cover grain cargo with waterproof sheets during road transit to mandis; exercise caution on slippery roads."
                )
            else:
                badge_lbl = "☀️ GREEN / मौसम अनुकूल - सामान्य कृषि व सुगम परिवहन"
                box_bg = "rgba(34, 197, 94, 0.15)"
                box_border = "#22c55e"
                text_col = "#86efac"
                irrigation_directive = (
                    "फसल आवश्यकतानुसार सामान्य अथवा हल्की सिंचाई जारी रख सकते हैं। जल स्तर सामान्य है।"
                    if is_hi else
                    "Safe to proceed with regular light irrigation as needed. Soil moisture levels are balanced."
                )
                transport_directive = (
                    "अनाज व उपज के मंडी परिवहन, सड़क ढुलाई तथा लोडिंग-अनलोडिंग के लिए परिस्थितियां पूरी तरह सुगम व सुरक्षित हैं।"
                    if is_hi else
                    "Transit conditions and road haulage routes to local mandis are optimal, clear, and safe."
                )

            # Strict HTML escaping to guarantee XSS immunity (CWE-79)
            safe_v_name = html.escape(str(v_name))
            safe_clean_input = html.escape(str(clean_input))
            safe_crop = html.escape(str(pred["crop"]))
            safe_irrigation = html.escape(irrigation_directive)
            safe_transport = html.escape(transport_directive)
            safe_holder = html.escape(str(pred["holder"]))
            safe_cell = html.escape(str(pred["cell_id"]))

            advisory_card_html = f"""
<div style="background-color: {box_bg}; border-left: 8px solid {box_border}; border: 1px solid {box_border}; padding: 22px; border-radius: 12px; margin-top: 20px; margin-bottom: 25px;">
<div style="font-size: 1.15rem; font-weight: 800; color: {text_col}; text-transform: uppercase; margin-bottom: 8px;">
{badge_lbl}
</div>
<div style="font-size: 1.35rem; font-weight: 700; color: #f8fafc; margin-bottom: 14px;">
{'ग्राम/मौजा: ' if is_hi else 'Village: '} {safe_v_name} | {'खसरा/गाटा: ' if is_hi else 'Khasra: '} {safe_clean_input} | {'फसल: ' if is_hi else 'Crop: '} {safe_crop}
</div>
<div style="margin-top: 10px; padding: 12px 14px; background: rgba(0, 0, 0, 0.25); border-radius: 8px; border-left: 4px solid #38bdf8;">
<b style="color: #38bdf8; font-size: 1.05rem;">💧 {'सिंचाई एवं जल प्रबंधन परामर्श (Irrigation Advisory):' if is_hi else 'Irrigation & Drainage Directive:'}</b>
<p style="margin: 4px 0 0 0; color: #f1f5f9; font-size: 0.98rem; line-height: 1.6;">{safe_irrigation}</p>
</div>
<div style="margin-top: 12px; padding: 12px 14px; background: rgba(0, 0, 0, 0.25); border-radius: 8px; border-left: 4px solid #facc15;">
<b style="color: #facc15; font-size: 1.05rem;">🚛 {'परिवहन एवं मंडी आवागमन निर्देश (Transport Advisory):' if is_hi else 'Transport & Mandi Haulage Directive:'}</b>
<p style="margin: 4px 0 0 0; color: #f1f5f9; font-size: 0.98rem; line-height: 1.6;">{safe_transport}</p>
</div>
</div>
"""
            st.markdown(textwrap.dedent(advisory_card_html), unsafe_allow_html=True)

            m_col1, m_col2, m_col3, m_col4 = st.columns(4)
            m_col1.metric("अनुमानित वर्षा (Downscaled Rain)", f"{pred['rain_mm']:.1f} mm")
            m_col2.metric("सतही हवा (Surface Wind)", f"{pred['wind_kmh']:.1f} km/h")
            m_col3.metric("टोपोग्राफिक वेटनेस (TWI)", f"{pred['twi']:.2f}")
            m_col4.metric("भूमि ऊंचाई (Elevation MSL)", f"{pred['elevation']:.1f} m")

            with st.expander("📋 भूलेख भूखंड एवं मॉडल विवरण (Cadastral Metadata)" if is_hi else "📋 Cadastral & Model Metadata", expanded=True):
                p_c1, p_c2, p_c3 = st.columns(3)
                p_c1.markdown(f"<p style='color: #f1f5f9;'><b>खसरा संख्या:</b> {safe_clean_input}</p>", unsafe_allow_html=True)
                p_c1.markdown(f"<p style='color: #f1f5f9;'><b>माइक्रो-सेल ID:</b> {safe_cell}</p>", unsafe_allow_html=True)
                p_c2.markdown(f"<p style='color: #f1f5f9;'><b>खातेदार का नाम:</b> {safe_holder}</p>", unsafe_allow_html=True)
                p_c2.markdown(f"<p style='color: #f1f5f9;'><b>मौजा:</b> {safe_v_name}</p>", unsafe_allow_html=True)
                p_c3.markdown(f"<p style='color: #f1f5f9;'><b>जलभराव जोखिम:</b> {'उच्च (Critical)' if pred['waterlog_risk'] == 1 else 'सामान्य (Safe)'}</p>", unsafe_allow_html=True)
                p_c3.markdown(f"<p style='color: #f1f5f9;'><b>स्रोत मॉडल:</b> {html.escape(PREDICTIONS_KHASRA_CSV)}</p>", unsafe_allow_html=True)

            spoken_report = (
                f"ग्राम {safe_v_name}, गाटा संख्या {safe_clean_input} की रिपोर्ट। वर्षा {pred['rain_mm']:.1f} मिलीमीटर। हवा {pred['wind_kmh']:.1f} किलोमीटर प्रति घंटा। "
                f"सिंचाई परामर्श: {irrigation_directive}। परिवहन निर्देश: {transport_directive}।"
                if is_hi else
                f"Report for Village {safe_v_name}, Khasra number {safe_clean_input}. Rainfall {pred['rain_mm']:.1f} millimeters. Wind speed {pred['wind_kmh']:.1f} kilometers per hour. "
                f"Irrigation action: {irrigation_directive}. Transport directive: {transport_directive}."
            )
            speak_page_text(spoken_report, st.session_state.language)
    else:
        fc_init_speech = (
            "खसरा वार मौसम, सिंचाई व परिवहन परामर्श पृष्ठ। कृपया अपना खसरा नंबर दर्ज करें, अपना गांव चुनें और मौसम का पूर्वानुमान बताएं बटन पर क्लिक करें।"
            if is_hi else
            "Plot-level weather, irrigation, and transport advisory page. Please enter your Khasra number, select your village, and click Tell Weather Forecast."
        )
        speak_page_text(fc_init_speech, st.session_state.language)

# -----------------------------------------------------------------------------
# 7. SARPANCH LOGIN SCREEN (CONSTANT-TIME PBKDF2 VERIFICATION & COOLDOWN)
# -----------------------------------------------------------------------------
elif st.session_state.role == "sarpanch" and st.session_state.current_page == "sarpanch_login":
    is_hi = (st.session_state.language == "हिंदी")

    b_col, _ = st.columns([3, 7])
    with b_col:
        if st.button("⬅️ " + ("वापस भूमिका चयन" if is_hi else "Back to Role Selection")):
            st.session_state.role = None
            st.rerun()

    sarpanch_login_head = f"""
<div style="margin-top: 10px; margin-bottom: 25px;">
    <h2 style="color: #4ade80;">🛡️ {'सरपंच लॉगिन' if is_hi else 'Sarpanch Login'}</h2>
    <p style="color: #cbd5e1;">{'अपने गांव/मौजा के लिए निर्धारित User ID और पासवर्ड से लॉगिन करें।' if is_hi else 'Login using village-assigned credentials.'}</p>
</div>
"""
    st.markdown(textwrap.dedent(sarpanch_login_head), unsafe_allow_html=True)

    with st.form("sarpanch_login_form"):
        s_village_labels = [f"{v['hi']} ({v['en']})" if is_hi else f"{v['en']} ({v['hi']})" for v in VILLAGE_LIST]
        s_selected_village = st.selectbox("ग्राम पंचायत / मौजा चुनें (Select Village)" if is_hi else "Select Village Panchayat", options=s_village_labels)
        s_id = st.text_input("User ID", placeholder="e.g. sarpanch_kalyani", max_chars=32)
        s_pass = st.text_input("Password", type="password", placeholder="••••••••", max_chars=32)
        s_submit = st.form_submit_button("🔓 लॉगिन करें (Login)" if is_hi else "🔓 Login", type="primary")

    if s_submit:
        # Rate-limiting Sarpanch authentication attempts (CWE-307)
        if is_rate_limited("sarpanch_auth", max_attempts=5, window_sec=180):
            st.error("अत्यधिक असफल प्रयास। कृपया 3 मिनट बाद पुनः प्रयास करें।" if is_hi else "Too many failed attempts. Account locked for 3 minutes.")
        else:
            v_idx = s_village_labels.index(s_selected_village)
            target_v = VILLAGE_LIST[v_idx]
            clean_s_id = s_id.strip()

            # Constant-time comparison on both ID and PBKDF2 hash (CWE-208)
            id_matches = hmac.compare_digest(clean_s_id, target_v["id"])
            pass_matches = verify_password_hash(s_pass.strip(), target_v["hash"])

            if id_matches and pass_matches:
                st.session_state.sarpanch_logged_in = True
                st.session_state.sarpanch_profile = {
                    "village": target_v["en"],
                    "village_hi": target_v["hi"],
                    "id": clean_s_id
                }
                st.session_state.current_page = "chief_home"
                st.success("लॉगिन सफल!" if is_hi else "Login successful!")
                st.rerun()
            else:
                st.error("अमान्य User ID या Password।" if is_hi else "Invalid User ID or Password.")

    with st.expander("🔑 " + ("डेमो क्रेडेंशियल दिशानिर्देश" if is_hi else "Demo Access Guidelines")):
        st.info("Demo User IDs are formatted as `sarpanch_<villagename>` with designated secure session keys." if not is_hi else "डेमो यूजर आईडी `sarpanch_<गाँव_का_नाम>` प्रारूप में निर्धारित हैं।")

    sarpanch_login_speech = (
        "सरपंच लॉगिन पृष्ठ। कृपया अपना ग्राम पंचायत चुनें, यूजर आई डी और पासवर्ड दर्ज कर लॉगिन करें।"
        if is_hi else
        "Sarpanch login page. Please select your village panchayat, enter your user ID and password to log in."
    )
    speak_page_text(sarpanch_login_speech, st.session_state.language)

# -----------------------------------------------------------------------------
# 8. SARPANCH HOME PANEL: TWO ACTIONS (SEE FORECAST vs CONFIRM FORECAST)
# -----------------------------------------------------------------------------
elif st.session_state.role == "sarpanch" and st.session_state.current_page == "chief_home":
    # Verify session authenticity
    if not st.session_state.sarpanch_logged_in:
        st.session_state.current_page = "sarpanch_login"
        st.rerun()

    is_hi = (st.session_state.language == "हिंदी")
    s_vill = html.escape(st.session_state.sarpanch_profile.get("village_hi" if is_hi else "village", "Barabanki"))

    top_l, top_r = st.columns([7, 3])
    with top_l:
        st.markdown(f"<h2 style='color: #4ade80;'>🛡️ {'सरपंच नियंत्रण कक्ष' if is_hi else 'Sarpanch Dashboard'} — {s_vill}</h2>", unsafe_allow_html=True)
    with top_r:
        if st.button("🚪 Logout", key="sarpanch_logout"):
            st.session_state.sarpanch_logged_in = False
            st.session_state.sarpanch_profile = {}
            st.session_state.role = None
            st.rerun()

    st.markdown("<p style='color: #cbd5e1;'>कृपया वांछित कार्य का चयन करें:</p>" if is_hi else "<p style='color: #cbd5e1;'>Select an operation:</p>", unsafe_allow_html=True)

    c1, c2 = st.columns(2)
    with c1:
        c1_html = f"""
<div style="background: rgba(30, 41, 59, 0.6); padding: 22px; border-radius: 12px; border: 1px solid #4ade80; text-align: center;">
    <h3 style="color: #4ade80;">{'🌤️ मौसम व सिंचाई/परिवहन पूर्वानुमान देखें' if is_hi else '🌤️ See Weather & Advisory'}</h3>
    <p style="color: #cbd5e1;">{'गांव के किसी भी खसरा संख्या हेतु तात्कालिक मौसम, सिंचाई व परिवहन परामर्श प्राप्त करें।' if is_hi else 'Check plot-level weather predictions, irrigation, and transit directives for any Khasra.'}</p>
</div>
"""
        st.markdown(textwrap.dedent(c1_html), unsafe_allow_html=True)
        if st.button("👉 " + ("पूर्वानुमान देखें (See Forecast)" if is_hi else "See Weather Forecast"), type="primary", use_container_width=True):
            st.session_state.current_page = "forecast"
            st.rerun()

    with c2:
        c2_html = f"""
<div style="background: rgba(30, 41, 59, 0.6); padding: 22px; border-radius: 12px; border: 1px solid #facc15; text-align: center;">
    <h3 style="color: #facc15;">{'📋 मौसम पूर्वानुमान सत्यापित करें' if is_hi else '📋 Confirm Weather Forecast'}</h3>
    <p style="color: #cbd5e1;">{'बताएं कि आपके गांव/मौजा के लिए की गई मौसम भविष्यवाणी सही थी या गलत।' if is_hi else 'Report whether the downscaled weather was RIGHT or WRONG on ground.'}</p>
</div>
"""
        st.markdown(textwrap.dedent(c2_html), unsafe_allow_html=True)
        if st.button("👉 " + ("पूर्वानुमान सत्यापित करें (Confirm Forecast)" if is_hi else "Confirm Weather Forecast"), type="primary", use_container_width=True):
            st.session_state.current_page = "confirm_forecast"
            st.rerun()

    chief_panel_speech = (
        f"सरपंच नियंत्रण कक्ष, ग्राम {s_vill}। यहां आपके पास दो विकल्प हैं। मौसम व परामर्श देखें या मौसम पूर्वानुमान सत्यापित करें।"
        if is_hi else
        f"Sarpanch Dashboard for village {s_vill}. You have two options: See Weather Forecast or Confirm Weather Forecast."
    )
    speak_page_text(chief_panel_speech, st.session_state.language)

# -----------------------------------------------------------------------------
# 9. SARPANCH CONFIRM WEATHER FORECAST (SECURED CSV EXPORT & VALIDATED UPLOAD)
# -----------------------------------------------------------------------------
elif st.session_state.role == "sarpanch" and st.session_state.current_page == "confirm_forecast":
    if not st.session_state.sarpanch_logged_in:
        st.session_state.current_page = "sarpanch_login"
        st.rerun()

    is_hi = (st.session_state.language == "हिंदी")
    s_vill_en = html.escape(st.session_state.sarpanch_profile.get("village", "Kalyani Basin"))
    s_vill_hi = html.escape(st.session_state.sarpanch_profile.get("village_hi", "कल्याणी कछार"))

    b_col, _ = st.columns([3, 7])
    with b_col:
        if st.button("⬅️ " + ("वापस सरपंच कक्ष" if is_hi else "Back to Sarpanch Home")):
            st.session_state.current_page = "chief_home"
            st.rerun()

    confirm_head_html = f"""
<div style="margin-top: 10px; margin-bottom: 25px;">
    <h2 style="color: #4ade80;">📷 {'मौसम पूर्वानुमान सत्यापन (Confirm Weather Forecast)' if is_hi else 'Confirm Weather Forecast Accuracy'}</h2>
    <p style="color: #cbd5e1;">{'ग्राम पंचायत: ' if is_hi else 'Village: '} <b>{s_vill_hi if is_hi else s_vill_en}</b> — {'बताएं कि मॉडल द्वारा की गई भविष्यवाणी धरातल पर सही थी अथवा गलत।' if is_hi else 'Report whether ground observations matched the downscaled predictions.'}</p>
</div>
"""
    st.markdown(textwrap.dedent(confirm_head_html), unsafe_allow_html=True)

    with st.form("verify_forecast_form"):
        verdict_options = [
            "✅ सही थी (Right / Correct Prediction)" if is_hi else "✅ Right / Correct Prediction",
            "❌ गलत थी (Wrong / Incorrect Prediction)" if is_hi else "❌ Wrong / Incorrect Prediction"
        ]
        verdict = st.radio(
            "क्या मौसम का पूर्वानुमान आपके गांव में सही था? (Was the forecast Right or Wrong?)" if is_hi else "Was the weather prediction accurate for your village/mauza?",
            options=verdict_options,
            index=0
        )
        khasra_ref = st.text_input("संबंधित खसरा / गाटा संख्या (वैकल्पिक)" if is_hi else "Khasra Number (Optional)", placeholder="e.g. 21, 50, 86", max_chars=20)
        observed_weather = st.selectbox(
            "वास्तविक धरातलीय स्थिति (Actual Observed Weather)" if is_hi else "Actual Observed Ground Condition",
            options=[
                "भारी बारिश हुई (Heavy Rain Observed)" if is_hi else "Heavy Rain Observed",
                "हल्की बारिश हुई (Light Drizzle Observed)" if is_hi else "Light Drizzle Observed",
                "तेज आंधी / हवाएं चलीं (High Winds/Storm)" if is_hi else "High Winds / Dust Storm",
                "मौसम बिल्कुल साफ व शुष्क रहा (Completely Dry/Sunny)" if is_hi else "Completely Dry / Sunny",
                "खेत में जलभराव हुआ (Severe Waterlogging Occurred)" if is_hi else "Severe Waterlogging Occurred"
            ]
        )
        uploaded_photo = st.file_uploader(
            "खेत अथवा मौसम का फोटो अपलोड करें (अधिकतम 5 MB)" if is_hi else "Upload field / sky condition photo (Max 5 MB)",
            type=["png", "jpg", "jpeg"]
        )
        notes = st.text_area("अतिरिक्त विवरण अथवा टिप्पणी (Notes)" if is_hi else "Additional Notes / Comments", placeholder="जैसे: दोपहर में तेज बारिश हुई...", max_chars=300)

        submit_verdict = st.form_submit_button("📤 सत्यापन जमा करें (Submit Verification)" if is_hi else "📤 Submit Verification", type="primary")

    if submit_verdict:
        # File upload validation (CWE-434)
        if uploaded_photo is not None:
            if uploaded_photo.size > 5 * 1024 * 1024:
                st.error("Uploaded image exceeds maximum allowable size (5 MB)." if not is_hi else "फोटो का आकार 5 MB से कम होना आवश्यक है।")
                st.stop()
            # Verify magic bytes for genuine image types
            header = uploaded_photo.getvalue()[:8]
            is_valid_image = (
                header.startswith(b"\x89PNG\r\n\x1a\n") or  # PNG
                header.startswith(b"\xff\xd8\xff")           # JPEG
            )
            if not is_valid_image:
                st.error("Invalid file header. Please upload a genuine PNG or JPEG file." if not is_hi else "अमान्य फ़ाइल प्रकार। कृपया वैध PNG या JPEG फोटो अपलोड करें।")
                st.stop()

        verdict_val = "RIGHT" if ("Right" in verdict or "सही" in verdict) else "WRONG"
        stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Sanitize all CSV cell inputs against CSV/Formula Injection (CWE-1236)
        clean_khasra = sanitize_csv_cell(re.sub(r"[^0-9a-zA-Z\u0900-\u097F\s/\-.,]", "", khasra_ref))
        clean_notes = sanitize_csv_cell(re.sub(r"[^\w\u0900-\u097F\s.,;:?!-]", "", notes))
        clean_village = sanitize_csv_cell(s_vill_en)
        clean_sarpanch_id = sanitize_csv_cell(st.session_state.sarpanch_profile.get("id", "sarpanch"))
        clean_observed = sanitize_csv_cell(observed_weather)

        file_exists = os.path.exists(FEEDBACK_CSV)
        try:
            with open(FEEDBACK_CSV, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)
                if not file_exists:
                    writer.writerow(["timestamp", "village", "sarpanch_id", "verdict", "khasra", "observed_condition", "notes"])
                writer.writerow([
                    stamp,
                    clean_village,
                    clean_sarpanch_id,
                    verdict_val,
                    clean_khasra,
                    clean_observed,
                    clean_notes
                ])
            
            success_msg = (
                f"धन्यवाद! ग्राम {s_vill_hi if is_hi else s_vill_en} के लिए सत्यापन दर्ज कर लिया गया है।"
                if is_hi else
                f"Thank you! Verification recorded for {s_vill_en} as {verdict_val}."
            )
            st.success(f"✅ {success_msg}")
            speak_page_text(success_msg, st.session_state.language)
        except Exception as exc:
            logger.error("Could not append feedback CSV record.")
            st.error("Could not write feedback. Please try again later." if not is_hi else "सत्यापन सहेजने में त्रुटि।")

    if os.path.exists(FEEDBACK_CSV):
        try:
            f_df = pd.read_csv(FEEDBACK_CSV)
            vill_feed = f_df[f_df["village"].astype(str).str.strip().str.lower() == s_vill_en.lower()]
            if not vill_feed.empty:
                st.markdown("<h4 style='color: #facc15; margin-top: 25px;'>📋 हाल के सत्यापन रिकॉर्ड (Recent Verifications)</h4>", unsafe_allow_html=True)
                st.dataframe(vill_feed.tail(5).iloc[::-1], use_container_width=True, hide_index=True)
        except Exception as exc:
            logger.warning("Could not read local feedback records.")

    confirm_init_speech = (
        f"मौसम पूर्वानुमान सत्यापन पृष्ठ। कृपया बताएं कि आपके ग्राम {s_vill_hi if is_hi else s_vill_en} में मौसम पूर्वानुमान सही था या गलत, और सत्यापन जमा करें।"
        if is_hi else
        f"Weather forecast verification page. Please report whether the forecast was Right or Wrong for your village {s_vill_en}, and submit your verification."
    )
    speak_page_text(confirm_init_speech, st.session_state.language)

