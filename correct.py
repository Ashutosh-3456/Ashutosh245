"""
retrain_from_feedback.py: Ingests ground-truth observations from weather_feedback_log.csv,
resolves cadastral Khasra plots, retrains the XGBoost models with instance re-weighting,
and updates the operational prediction datasets.
"""

import json
import os
import joblib
import pandas as pd
from sklearn.ensemble import GradientBoostingClassifier, GradientBoostingRegressor

try:
    from xgboost import XGBClassifier, XGBRegressor
except ImportError:
    XGBRegressor = GradientBoostingRegressor
    XGBClassifier = GradientBoostingClassifier

# File Paths
FEEDBACK_CSV = "weather_feedback_log.csv"
if not os.path.exists(FEEDBACK_CSV):
    FEEDBACK_CSV = "training_uploads/weather_feedback_log.csv"

TRAIN_DATA = "grid_training_dataset.csv"
CELLS_CSV = "nasadem_real_micro_terrain_64_cells.csv"
BHULEKH_CSV = "bhulekh_khasra_grid_mapping_demo_names.csv"
SYNOPTIC_FILE = "latest_synoptic_weather.json"

MODEL_RAIN_PATH = "xgb_model_rain.pkl"
MODEL_WIND_PATH = "xgb_model_wind.pkl"
MODEL_WATERLOG_PATH = "xgb_model_waterlog.pkl"

OUTPUT_CELL_PREDICTIONS = "sukshmavrishti_64_cell_predictions.csv"
OUTPUT_KHASRA_FORECAST = "latest_khasra_weather_forecast.csv"

FEATURE_COLS = [
    "elevation_m", "slope_deg", "aspect_deg", "twi", "roughness_z0",
    "temp_anomaly_c", "moisture_feedback", "dist_updraft_km",
    "drainage_density_km_km2", "soil_saturation_cap_pct",
    "synoptic_rain_mm", "synoptic_temp_c", "synoptic_wind_kmh",
    "synoptic_winddir_deg", "synoptic_rh_pct"
]


def resolve_khasra_cell(khasra_val, village_val, df_cells, df_bhulekh=None):
    """
    Resolves the exact micro-terrain cell for a given Khasra and Village.
    """
    k_str = str(khasra_val).strip().lower() if pd.notna(khasra_val) else ""
    v_str = str(village_val).strip().lower() if pd.notna(village_val) else ""

    # 1. Search in Bhulekh cadastral mapping
    if df_bhulekh is not None and k_str:
        m = df_bhulekh[df_bhulekh["khasra_gata_number"].astype(str).str.strip().str.lower() == k_str]
        if not m.empty:
            m_v = m[
                (m["village_mauza_en"].astype(str).str.lower().str.contains(v_str, na=False)) |
                (m["village_mauza_hi"].astype(str).str.contains(v_str, na=False))
            ]
            chosen = m_v.iloc[0] if not m_v.empty else m.iloc[0]
            cell_match = df_cells[df_cells["cell_id"] == chosen["cell_id"]]
            if not cell_match.empty:
                return cell_match.iloc[0], chosen

    # 2. Search in NASADEM sample_khasra_numbers
    if k_str:
        for _, row in df_cells.iterrows():
            samples = [s.strip().lower() for s in str(row.get("sample_khasra_numbers", "")).split(",")]
            if k_str in samples or k_str in str(row.get("sample_khasra_numbers", "")).lower():
                return row, None

    # 3. Fallback to village name
    if v_str:
        sub = df_cells[
            (df_cells["village_mauza_en"].astype(str).str.lower().str.contains(v_str, na=False)) |
            (df_cells["village_mauza_hi"].astype(str).str.contains(v_str, na=False))
        ]
        if not sub.empty:
            return sub.iloc[0], None

    return df_cells.iloc[0], None


def generate_advisories(p_rain, p_wind, twi, wl, crop, khasras, aspect_deg):
    """
    Builds comprehensive bilingual advisories including field, irrigation, and transit directives.
    """
    if wl == 1 or twi >= 11.2 or p_rain >= 35.0:
        st_en = "CRITICAL: High Waterlogging & Transport Hazard"
        hi_adv = (
            f"गाटा संख्या ({khasras}) के लिए चेतावनी: TWI ({twi:.2f}) अधिक होने से खेत में भारी जलभराव का जोखिम है। "
            f"• फसल निर्देश: {crop} में कीटनाशक व उर्वरक छिड़काव तुरंत रोकें। "
            f"• सिंचाई परामर्श: नलकूप व नहर से सिंचाई तत्काल पूर्णतः बंद रखें। ढलान दिशा ({aspect_deg:.0f}°) में मेड़ काटकर निकासी नाली तुरंत खोलें। "
            f"• परिवहन परामर्श: ग्रामीण संपर्क मार्गों व कच्ची पटरियों पर फिसलन व जलभराव की आशंका है। खुली ट्रैक्टर-ट्रॉली में अनाज मंडी ले जाने से बचें, कटी फसल को तिरपाल से सुरक्षित बांधें।"
        )
        en_adv = (
            f"Critical Alert for plots ({khasras}): High TWI ({twi:.2f}) indicates severe waterlogging and runoff risk. "
            f"• Field Action: Suspend chemical spraying and top-dressing in {crop}. "
            f"• Irrigation Advisory: Halt all canal and tube-well irrigation immediately; unclog drainage furrows along {aspect_deg:.0f}° slope. "
            f"• Transport Advisory: High risk of waterlogged rural haul tracks; avoid transporting harvested produce in open trolleys and secure all grain with waterproof tarpaulins."
        )
    elif p_rain >= 10.0:
        st_en = "MODERATE: Rainy Weather - Irrigation Postponement"
        hi_adv = (
            f"गाटा संख्या ({khasras}) के लिए परामर्श: मध्यम वर्षा ({p_rain:.1f} मिमी) व हवा ({p_wind:.1f} किमी/घंटा) संभावित है। "
            f"• फसल निर्देश: {crop} में कटी फसल को खलिहान में सुरक्षित करें। "
            f"• सिंचाई परामर्श: आगामी 36 से 48 घंटों तक निर्धारित सिंचाई स्थगित रखें और वर्षा जल का सदुपयोग करें। "
            f"• परिवहन परामर्श: मंडी परिवहन हेतु अनाज की बोरियों को वाटरप्रूफ तिरपाल से अच्छी तरह ढककर सुरक्षित ले जाएं।"
        )
        en_adv = (
            f"Moderate Advisory for plots ({khasras}): Moderate rainfall ({p_rain:.1f} mm) and winds ({p_wind:.1f} km/h) forecasted. "
            f"• Field Action: Ensure harvested produce on threshing floors is protected. "
            f"• Irrigation Advisory: Postpone scheduled irrigation for 36-48 hours to prevent localized water stagnation. "
            f"• Transport Advisory: Secure grain sacks with waterproof tarpaulins during road transit to mandis."
        )
    else:
        st_en = "NORMAL: Favorable Field & Transit Conditions"
        hi_adv = (
            f"गाटा संख्या ({khasras}) के लिए सूचना: मौसम शुष्क व अनुकूल है। "
            f"• फसल निर्देश: {crop} में सामान्य कृषि कार्य व निराई-गुड़ाई सुचारू रखें। "
            f"• सिंचाई परामर्श: फसल आवश्यकतानुसार सामान्य अथवा हल्की सिंचाई जारी रख सकते हैं। "
            f"• परिवहन परामर्श: अनाज व फसल के मंडी परिवहन, ढुलाई तथा लोडिंग-अनलोडिंग के लिए परिस्थितियां पूरी तरह सुरक्षित व सुगम हैं।"
        )
        en_adv = (
            f"Favorable Conditions for plots ({khasras}): Weather is stable and dry. "
            f"• Field Action: Continue regular field weeding and crop maintenance in {crop}. "
            f"• Irrigation Advisory: Safe window to proceed with scheduled light irrigation as required. "
            f"• Transport Advisory: Haulage routes and weather conditions are optimal for mandi transit and grain handling."
        )
    return st_en, hi_adv, en_adv


def retrain_from_feedback():
    if not os.path.exists(FEEDBACK_CSV):
        print(f"Error: Feedback log file '{FEEDBACK_CSV}' not found.")
        return

    print(f"Reading feedback from '{FEEDBACK_CSV}'...")
    df_fb = pd.read_csv(FEEDBACK_CSV).dropna(subset=["verdict"])
    if df_fb.empty:
        print("No feedback entries found to process.")
        return

    df_cells = pd.read_csv(CELLS_CSV)
    df_bhulekh = pd.read_csv(BHULEKH_CSV) if os.path.exists(BHULEKH_CSV) else None
    df_base = pd.read_csv(TRAIN_DATA)

    # Ingest regional synoptic forcing
    syn = {
        "regional_precipitation_24h_mm": 25.0,
        "regional_temp_c": 28.0,
        "regional_windspeed_kmh": 16.0,
        "regional_winddir_deg": 100.0,
        "regional_relative_humidity": 82.0
    }
    if os.path.exists(SYNOPTIC_FILE):
        try:
            with open(SYNOPTIC_FILE, "r", encoding="utf-8") as f:
                syn.update(json.load(f))
        except Exception:
            pass

    corrected_samples = []

    for _, row in df_fb.iterrows():
        kh = row.get("khasra")
        village = row.get("village")
        verdict = str(row.get("verdict", "")).strip().upper()
        obs = str(row.get("observed_condition", ""))

        cell, bhulekh_rec = resolve_khasra_cell(kh, village, df_cells, df_bhulekh)
        is_wrong = verdict in ["WRONG", "NO", "FALSE", "0", "गलत", "नहीं"]

        # Derive ground truth based on ground observation
        if "Heavy Rain" in obs or "भारी बारिश" in obs:
            actual_rain = 48.0 if is_wrong else 36.0
            actual_wl = 1 if (is_wrong or float(cell["twi"]) >= 10.5) else 0
            actual_wind = 18.0
        elif "Light" in obs or "हल्की" in obs:
            actual_rain = 5.0
            actual_wl = 0
            actual_wind = 12.0
        elif "Dry" in obs or "Sunny" in obs or "साफ" in obs:
            actual_rain = 0.0
            actual_wl = 0
            actual_wind = 8.0
        elif "Waterlogging" in obs or "जलभराव" in obs:
            actual_rain = 45.0
            actual_wl = 1
            actual_wind = 16.0
        else:
            actual_rain = 30.0
            actual_wl = 1 if is_wrong else 0
            actual_wind = 15.0

        weight = 4.0 if is_wrong else 2.0

        corrected_samples.append({
            "cell_id": cell["cell_id"],
            "elevation_m": float(cell["elevation_m"]),
            "slope_deg": float(cell["slope_deg"]),
            "aspect_deg": float(cell["aspect_deg"]),
            "twi": float(cell["twi"]),
            "roughness_z0": float(cell["roughness_z0"]),
            "temp_anomaly_c": float(cell["temp_anomaly_c"]),
            "moisture_feedback": float(cell["moisture_feedback"]),
            "dist_updraft_km": float(cell.get("dist_updraft_km", 3.26)),
            "drainage_density_km_km2": float(cell.get("drainage_density_km_km2", 1.25)),
            "soil_saturation_cap_pct": float(cell.get("soil_saturation_cap_pct", 55.0)),
            "synoptic_rain_mm": float(syn["regional_precipitation_24h_mm"]),
            "synoptic_temp_c": float(syn["regional_temp_c"]),
            "synoptic_wind_kmh": float(syn["regional_windspeed_kmh"]),
            "synoptic_winddir_deg": float(syn["regional_winddir_deg"]),
            "synoptic_rh_pct": float(syn["regional_relative_humidity"]),
            "target_downscaled_rain_mm": actual_rain,
            "target_downscaled_wind_kmh": actual_wind,
            "target_waterlogging_risk": actual_wl,
            "sample_weight": weight
        })

    # Combine baseline dataset with weighted feedback samples
    df_corrected = pd.DataFrame(corrected_samples)
    df_base["sample_weight"] = 1.0
    combined = pd.concat([df_base, df_corrected], ignore_index=True)

    X = combined[FEATURE_COLS]
    w = combined["sample_weight"]

    # 1. Retrain Rainfall Regressor
    print("Retraining Rainfall Model with feedback...")
    m_rain = XGBRegressor(n_estimators=120, learning_rate=0.07, max_depth=4, random_state=42)
    m_rain.fit(X, combined["target_downscaled_rain_mm"], sample_weight=w)
    joblib.dump(m_rain, MODEL_RAIN_PATH)

    # 2. Retrain Wind Regressor
    print("Retraining Wind Speed Model with feedback...")
    m_wind = XGBRegressor(n_estimators=100, learning_rate=0.06, max_depth=4, random_state=42)
    m_wind.fit(X, combined["target_downscaled_wind_kmh"], sample_weight=w)
    joblib.dump(m_wind, MODEL_WIND_PATH)

    # 3. Retrain Waterlogging Classifier
    print("Retraining Waterlogging Model with feedback...")
    m_wl = XGBClassifier(n_estimators=100, learning_rate=0.08, max_depth=4, random_state=42)
    m_wl.fit(X, combined["target_waterlogging_risk"], sample_weight=w)
    joblib.dump(m_wl, MODEL_WATERLOG_PATH)

    # Regenerate prediction outputs
    print("Generating updated 64-cell and Khasra forecast datasets...")
    df_inf = df_cells.copy()
    df_inf["synoptic_rain_mm"] = syn["regional_precipitation_24h_mm"]
    df_inf["synoptic_temp_c"] = syn["regional_temp_c"]
    df_inf["synoptic_wind_kmh"] = syn["regional_windspeed_kmh"]
    df_inf["synoptic_winddir_deg"] = syn["regional_winddir_deg"]
    df_inf["synoptic_rh_pct"] = syn["regional_relative_humidity"]

    X_inf = df_inf[FEATURE_COLS]
    df_inf["pred_downscaled_rain_mm"] = [round(float(v), 2) for v in m_rain.predict(X_inf)]
    df_inf["pred_downscaled_wind_kmh"] = [round(float(v), 2) for v in m_wind.predict(X_inf)]
    df_inf["pred_waterlogging_risk"] = [int(v) for v in m_wl.predict(X_inf)]

    statuses, advisories_hi, advisories_en = [], [], []
    for _, r in df_inf.iterrows():
        st_en, hi, en = generate_advisories(
            r["pred_downscaled_rain_mm"],
            r["pred_downscaled_wind_kmh"],
            r["twi"],
            r["pred_waterlogging_risk"],
            r["dominant_crop"],
            r["sample_khasra_numbers"],
            r["aspect_deg"]
        )
        statuses.append(st_en)
        advisories_hi.append(hi)
        advisories_en.append(en)

    df_inf["advisory_status_en"] = statuses
    df_inf["cadastral_advisory_hi"] = advisories_hi
    df_inf["cadastral_advisory_en"] = advisories_en
    df_inf.to_csv(OUTPUT_CELL_PREDICTIONS, index=False)

    if df_bhulekh is not None:
        df_khasra_forecast = df_bhulekh.merge(
            df_inf[[
                "cell_id", "elevation_m", "slope_deg", "aspect_deg", "twi", "roughness_z0",
                "pred_downscaled_rain_mm", "pred_downscaled_wind_kmh", "pred_waterlogging_risk",
                "advisory_status_en", "cadastral_advisory_hi", "cadastral_advisory_en"
            ]],
            on="cell_id",
            how="left"
        )
        df_khasra_forecast.to_csv(OUTPUT_KHASRA_FORECAST, index=False)

    print(f"Retraining complete. Recalibrated {len(corrected_samples)} feedback entries and updated all prediction outputs.")


if __name__ == "__main__":
    retrain_from_feedback()