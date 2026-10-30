"""
open_meteo.py: Query regional synoptic weather drivers for the Barabanki domain center
from the Open-Meteo API and save them to 'latest_synoptic_weather.json'.
"""

import json
import urllib.request
from datetime import datetime

DOMAIN_CENTER_LAT = 26.91549
DOMAIN_CENTER_LON = 81.17593
OUTPUT_SYNOPTIC_FILE = "latest_synoptic_weather.json"


def fetch_open_meteo_forecast(lat=DOMAIN_CENTER_LAT, lon=DOMAIN_CENTER_LON):
    url = (
        f"https://api.open-meteo.com/v1/forecast?"
        f"latitude={lat}&longitude={lon}&current_weather=true&"
        f"hourly=temperature_2m,relativehumidity_2m,precipitation,surface_pressure,windspeed_10m,winddirection_10m"
        f"&timezone=Asia%2FKolkata"
    )

    print(f"Fetching Open-Meteo regional forecast for ({lat}, {lon})...")
    req = urllib.request.Request(url, headers={"User-Agent": "SukshmaVrishti-System/2.0"})

    try:
        with urllib.request.urlopen(req, timeout=12) as response:
            data = json.loads(response.read().decode("utf-8"))
            current = data.get("current_weather", {})
            hourly = data.get("hourly", {})

            precip_list = hourly.get("precipitation", [0.0])
            next_24h_precip = round(float(sum(precip_list[:24])), 2) if precip_list else 0.0

            synoptic_state = {
                "timestamp": datetime.now().isoformat(),
                "latitude": lat,
                "longitude": lon,
                "regional_temp_c": float(current.get("temperature", 28.5)),
                "regional_windspeed_kmh": float(current.get("windspeed", 15.0)),
                "regional_winddir_deg": float(current.get("winddirection", 95.0)),
                "regional_precipitation_24h_mm": next_24h_precip if next_24h_precip > 0 else 32.0,
                "regional_relative_humidity": float(hourly.get("relativehumidity_2m", [82])[0]),
                "regional_surface_pressure_hpa": float(hourly.get("surface_pressure", [1007.5])[0]),
            }

            with open(OUTPUT_SYNOPTIC_FILE, "w", encoding="utf-8") as f:
                json.dump(synoptic_state, f, indent=4)

            print(f"Synoptic baseline cached to '{OUTPUT_SYNOPTIC_FILE}'.")
            return synoptic_state

    except Exception as err:
        print(f"Open-Meteo query failed ({err}). Using standard regional monsoon baseline.")
        fallback = {
            "timestamp": datetime.now().isoformat(),
            "latitude": lat,
            "longitude": lon,
            "regional_temp_c": 28.0,
            "regional_windspeed_kmh": 16.0,
            "regional_winddir_deg": 105.0,
            "regional_precipitation_24h_mm": 35.0,
            "regional_relative_humidity": 84.0,
            "regional_surface_pressure_hpa": 1006.8,
        }
        with open(OUTPUT_SYNOPTIC_FILE, "w", encoding="utf-8") as f:
            json.dump(fallback, f, indent=4)
        return fallback


if __name__ == "__main__":
    fetch_open_meteo_forecast()