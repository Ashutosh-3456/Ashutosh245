"""
predict_grid.py: Ingests synoptic forecast and micro-terrain variables, performs ML inference,
merges predictions with Bhulekh cadastral records, and synthesizes plot-level advisories
with explicit directives for Irrigation and Agricultural Transport.
"""

import json
import joblib
import pandas as pd

TERRAIN_CSV = "nasadem_real_micro_terrain_64_cells.csv"
BHULEKH_CSV = "bhulekh_khasra_grid_mapping_demo_names.csv"
SYNOPTIC_FILE = "latest_synoptic_weather.json"

MODEL_RAIN_PATH = "xgb_model_rain.pkl"
MODEL_WIND_PATH = "xgb_model_wind.pkl"
MODEL_WATERLOG_PATH = "xgb_model_waterlog.pkl"

OUTPUT_CELL_PREDICTIONS = "sukshmavrishti_64_cell_predictions.csv"
OUTPUT_KHASRA_FORECAST = "latest_khasra_weather_forecast.csv"

FEATURES = [
    "elevation_m", "slope_deg", "aspect_deg", "twi", "roughness_z0",
    "temp_anomaly_c", "moisture_feedback", "dist_updraft_km",
    "drainage_density_km_km2", "soil_saturation_cap_pct",
    "synoptic_rain_mm", "synoptic_temp_c", "synoptic_wind_kmh",
    "synoptic_winddir_deg", "synoptic_rh_pct"
]


def generate_comprehensive_advisory(p_rain, p_wind, twi, wl, crop, khasras, aspect_deg):
    """
    Generates bilingual advisories covering field protection, irrigation action,
    and road transport / mandi haulage safety.
    """
    if wl == 1 or twi >= 11.2 or p_rain >= 35.0:
        status_en = "CRITICAL: High Waterlogging & Transport Hazard"
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
        status_en = "MODERATE: Rainy Weather - Irrigation Postponement"
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
        status_en = "NORMAL: Favorable Field & Transit Conditions"
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
    return status_en, hi_adv, en_adv


def run_inference():
    print(f"Loading trained models...")
    model_rain = joblib.load(MODEL_RAIN_PATH)
    model_wind = joblib.load(MODEL_WIND_PATH)
    model_waterlog = joblib.load(MODEL_WATERLOG_PATH)

    df_grid = pd.read_csv(TERRAIN_CSV)
    with open(SYNOPTIC_FILE, "r", encoding="utf-8") as f:
        syn = json.load(f)

    # Inject synoptic conditions into the grid
    df_grid["synoptic_rain_mm"] = syn["regional_precipitation_24h_mm"]
    df_grid["synoptic_temp_c"] = syn["regional_temp_c"]
    df_grid["synoptic_wind_kmh"] = syn["regional_windspeed_kmh"]
    df_grid["synoptic_winddir_deg"] = syn["regional_winddir_deg"]
    df_grid["synoptic_rh_pct"] = syn["regional_relative_humidity"]

    X_infer = df_grid[FEATURES]
    df_grid["pred_downscaled_rain_mm"] = [round(float(v), 2) for v in model_rain.predict(X_infer)]
    df_grid["pred_downscaled_wind_kmh"] = [round(float(v), 2) for v in model_wind.predict(X_infer)]
    df_grid["pred_waterlogging_risk"] = [int(v) for v in model_waterlog.predict(X_infer)]

    statuses, advisories_hi, advisories_en = [], [], []

    for _, r in df_grid.iterrows():
        st_en, hi_adv, en_adv = generate_comprehensive_advisory(
            p_rain=r["pred_downscaled_rain_mm"],
            p_wind=r["pred_downscaled_wind_kmh"],
            twi=r["twi"],
            wl=r["pred_waterlogging_risk"],
            crop=r["dominant_crop"],
            khasras=r["sample_khasra_numbers"],
            aspect_deg=r["aspect_deg"]
        )
        statuses.append(st_en)
        advisories_hi.append(hi_adv)
        advisories_en.append(en_adv)

    df_grid["advisory_status_en"] = statuses
    df_grid["cadastral_advisory_hi"] = advisories_hi
    df_grid["cadastral_advisory_en"] = advisories_en

    # Export cell-level downscaling matrix
    df_grid.to_csv(OUTPUT_CELL_PREDICTIONS, index=False, encoding="utf-8-sig")
    print(f"Saved cell-level downscaled predictions to '{OUTPUT_CELL_PREDICTIONS}'.")

    # Merge with Bhulekh cadastral dataset to provide plot-level forecasts
    if pd.io.common.file_exists(BHULEKH_CSV):
        df_bhulekh = pd.read_csv(BHULEKH_CSV)
        df_khasra_out = df_bhulekh.merge(
            df_grid[[
                "cell_id", "elevation_m", "slope_deg", "aspect_deg", "twi", "roughness_z0",
                "pred_downscaled_rain_mm", "pred_downscaled_wind_kmh", "pred_waterlogging_risk",
                "advisory_status_en", "cadastral_advisory_hi", "cadastral_advisory_en"
            ]],
            on="cell_id",
            how="left"
        )
        df_khasra_out.to_csv(OUTPUT_KHASRA_FORECAST, index=False, encoding="utf-8-sig")
        print(f"Saved plot-level cadastral forecasts to '{OUTPUT_KHASRA_FORECAST}'.")


if __name__ == "__main__":
    run_inference()