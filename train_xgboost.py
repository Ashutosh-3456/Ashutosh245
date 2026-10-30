"""
train_xgboost.py: Trains, evaluates, and serializes machine learning models for SūkṣmaVṛṣṭi:
  1. Micro-precipitation downscaling (XGBRegressor)
  2. Surface aerodynamic wind deceleration (XGBRegressor)
  3. Plot-level waterlogging vulnerability classification (XGBClassifier)

Trained using grid_training_dataset.csv (derived from nasadem_real_micro_terrain_64_cells.csv).
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    mean_squared_error,
    r2_score,
)
from sklearn.model_selection import train_test_split

# Safe import: utilizes XGBoost if available, otherwise falls back to Scikit-Learn Gradient Boosting
try:
    from xgboost import XGBClassifier, XGBRegressor
    BACKEND_NAME = "XGBoost"
except ImportError:
    from sklearn.ensemble import (
        GradientBoostingClassifier as XGBClassifier,
        GradientBoostingRegressor as XGBRegressor,
    )
    BACKEND_NAME = "Scikit-Learn GradientBoosting (Fallback)"

# File paths
TRAIN_DATA_FILE = "grid_training_dataset.csv"
MODEL_RAIN_PATH = "xgb_model_rain.pkl"
MODEL_WIND_PATH = "xgb_model_wind.pkl"
MODEL_WATERLOG_PATH = "xgb_model_waterlog.pkl"

# 15 boundary-layer and physical micro-terrain features
FEATURE_COLS = [
    "elevation_m",
    "slope_deg",
    "aspect_deg",
    "twi",
    "roughness_z0",
    "temp_anomaly_c",
    "moisture_feedback",
    "dist_updraft_km",
    "drainage_density_km_km2",
    "soil_saturation_cap_pct",
    "synoptic_rain_mm",
    "synoptic_temp_c",
    "synoptic_wind_kmh",
    "synoptic_winddir_deg",
    "synoptic_rh_pct",
]


def load_and_split_data(csv_path: str):
    """Loads feature matrix and splits into train and validation sets."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(
            f"Training dataset '{csv_path}' not found. Please run 'generate_train_grid.py' first."
        )

    df = pd.read_csv(csv_path)

    # Check for missing feature columns and alert if any are absent
    missing = [col for col in FEATURE_COLS if col not in df.columns]
    if missing:
        raise ValueError(f"Missing required columns in dataset: {missing}")

    X = df[FEATURE_COLS]
    y_rain = df["target_downscaled_rain_mm"]
    y_wind = df["target_downscaled_wind_kmh"]
    y_waterlog = df["target_waterlogging_risk"]

    return train_test_split(
        X, y_rain, y_wind, y_waterlog, test_size=0.20, random_state=42
    )


def train_models():
    print(f"ML Framework: {BACKEND_NAME}")
    print(f"Loading training features from '{TRAIN_DATA_FILE}'...")
    (
        X_train,
        X_val,
        y_r_train,
        y_r_val,
        y_w_train,
        y_w_val,
        y_wl_train,
        y_wl_val,
    ) = load_and_split_data(TRAIN_DATA_FILE)

    print(
        f"Dataset split: {len(X_train)} training instances | {len(X_val)} validation instances\n"
    )

    # -------------------------------------------------------------------------
    # 1. Downscaled Precipitation Model (Regressor)
    # -------------------------------------------------------------------------
    print("--- Training Model 1/3: Downscaled Precipitation (mm) ---")
    model_rain = XGBRegressor(
        n_estimators=150,
        learning_rate=0.06,
        max_depth=5,
        random_state=42,
    )
    model_rain.fit(X_train, y_r_train)

    r_pred = model_rain.predict(X_val)
    r2_r = r2_score(y_r_val, r_pred)
    rmse_r = np.sqrt(mean_squared_error(y_r_val, r_pred))
    print(f"  R² Score: {r2_r:.4f}")
    print(f"  RMSE:     {rmse_r:.3f} mm")
    joblib.dump(model_rain, MODEL_RAIN_PATH)
    print(f"  Saved:    {MODEL_RAIN_PATH}\n")

    # -------------------------------------------------------------------------
    # 2. Surface Wind Friction Model (Regressor)
    # -------------------------------------------------------------------------
    print("--- Training Model 2/3: Surface Wind Speed (km/h) ---")
    model_wind = XGBRegressor(
        n_estimators=120,
        learning_rate=0.05,
        max_depth=4,
        random_state=42,
    )
    model_wind.fit(X_train, y_w_train)

    w_pred = model_wind.predict(X_val)
    r2_w = r2_score(y_w_val, w_pred)
    rmse_w = np.sqrt(mean_squared_error(y_w_val, w_pred))
    print(f"  R² Score: {r2_w:.4f}")
    print(f"  RMSE:     {rmse_w:.3f} km/h")
    joblib.dump(model_wind, MODEL_WIND_PATH)
    print(f"  Saved:    {MODEL_WIND_PATH}\n")

    # -------------------------------------------------------------------------
    # 3. Waterlogging Risk Classifier (Binary)
    # -------------------------------------------------------------------------
    print("--- Training Model 3/3: Cadastral Waterlogging Risk (Binary) ---")
    model_waterlog = XGBClassifier(
        n_estimators=100,
        learning_rate=0.08,
        max_depth=4,
        random_state=42,
    )
    model_waterlog.fit(X_train, y_wl_train)

    wl_pred = model_waterlog.predict(X_val)
    acc_wl = accuracy_score(y_wl_val, wl_pred)
    print(f"  Accuracy: {acc_wl * 100:.2f}%\n")
    print("  Classification Report:")
    print(classification_report(y_wl_val, wl_pred, digits=4))
    joblib.dump(model_waterlog, MODEL_WATERLOG_PATH)
    print(f"  Saved:    {MODEL_WATERLOG_PATH}\n")

    # Feature Importance Diagnostic
    importance_df = pd.DataFrame(
        {
            "Feature": FEATURE_COLS,
            "Rainfall_Importance": model_rain.feature_importances_,
            "Wind_Importance": model_wind.feature_importances_,
            "Waterlog_Importance": model_waterlog.feature_importances_,
        }
    ).sort_values(by="Waterlog_Importance", ascending=False)

    print("--- Feature Importances ---")
    print(importance_df.to_string(index=False))
    print("\nTraining completed successfully.")


if __name__ == "__main__":
    train_models()