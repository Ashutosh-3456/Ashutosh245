"""
generate_train_grid.py: Generates the multi-event synthetic-historical training feature store
by coupling NASADEM physical micro-terrain variables with synoptic atmospheric forcing.
"""

import numpy as np
import pandas as pd

TERRAIN_CSV = "nasadem_real_micro_terrain_64_cells.csv"
OUTPUT_TRAIN_DATA = "grid_training_dataset.csv"


def build_training_matrix(n_events=60):
    print(f"Loading micro-terrain variables from '{TERRAIN_CSV}'...")
    df_terrain = pd.read_csv(TERRAIN_CSV)
    np.random.seed(42)
    records = []

    for event_id in range(n_events):
        reg_rain = float(np.random.choice([0.0, 5.0, 18.0, 35.0, 65.0, 95.0], p=[0.15, 0.20, 0.25, 0.20, 0.12, 0.08]))
        reg_temp = float(np.random.uniform(18.0, 38.0))
        reg_wind = float(np.random.uniform(6.0, 32.0))
        reg_winddir = float(np.random.uniform(0.0, 360.0))
        reg_rh = float(np.random.uniform(45.0, 98.0))

        for _, cell in df_terrain.iterrows():
            elev = float(cell["elevation_m"])
            slope = float(cell["slope_deg"])
            aspect = float(cell["aspect_deg"])
            twi = float(cell["twi"])
            z0 = float(cell["roughness_z0"])
            dt = float(cell["temp_anomaly_c"])
            mf = float(cell["moisture_feedback"])
            du = float(cell.get("dist_updraft_km", 3.26))
            dd = float(cell.get("drainage_density_km_km2", 1.25))
            sc = float(cell.get("soil_saturation_cap_pct", 55.0))

            # Boundary-layer interaction: Orographic slope vs wind azimuth
            wind_aspect_delta = np.radians(abs(reg_winddir - aspect))
            orographic_factor = np.cos(wind_aspect_delta) * (slope / 4.0)

            # Micro-precipitation downscaling physics
            if reg_rain > 0:
                twi_effect = (twi - 10.86) * 0.12
                updraft_effect = max(0.0, (4.0 - du) / 4.0) * 0.10
                thermal_effect = max(0.0, dt) * 0.06
                downscaled_rain = reg_rain * (1.0 + twi_effect + orographic_factor * 0.15 + updraft_effect + thermal_effect)
                downscaled_rain = max(0.0, round(float(downscaled_rain + np.random.normal(0, 0.6)), 2))
            else:
                downscaled_rain = 0.0

            # Surface wind friction (logarithmic boundary layer deceleration)
            wind_friction_ratio = np.log(10.0 / max(0.01, z0)) / np.log(10.0 / 0.05)
            downscaled_wind = round(float(reg_wind * np.clip(wind_friction_ratio, 0.35, 1.05)), 2)

            # Cadastral waterlogging risk classification
            waterlog_score = (downscaled_rain * 0.45) + ((twi - 9.88) * 4.5) - (slope * 2.2) + ((sc - 50.0) * 0.15)
            waterlog_risk = 1 if waterlog_score > 24.0 else 0

            records.append({
                "event_id": event_id,
                "cell_id": cell["cell_id"],
                "elevation_m": elev,
                "slope_deg": slope,
                "aspect_deg": aspect,
                "twi": twi,
                "roughness_z0": z0,
                "temp_anomaly_c": dt,
                "moisture_feedback": mf,
                "dist_updraft_km": du,
                "drainage_density_km_km2": dd,
                "soil_saturation_cap_pct": sc,
                "synoptic_rain_mm": reg_rain,
                "synoptic_temp_c": reg_temp,
                "synoptic_wind_kmh": reg_wind,
                "synoptic_winddir_deg": reg_winddir,
                "synoptic_rh_pct": reg_rh,
                "target_downscaled_rain_mm": downscaled_rain,
                "target_downscaled_wind_kmh": downscaled_wind,
                "target_waterlogging_risk": waterlog_risk,
            })

    df_out = pd.DataFrame(records)
    df_out.to_csv(OUTPUT_TRAIN_DATA, index=False, encoding="utf-8-sig")
    print(f"Generated {len(df_out)} training samples saved to '{OUTPUT_TRAIN_DATA}'.")


if __name__ == "__main__":
    build_training_matrix()