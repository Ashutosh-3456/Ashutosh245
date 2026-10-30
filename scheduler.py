import time
import subprocess
from apscheduler.schedulers.background import BackgroundScheduler

def run_weather_pipeline():
    print("[Automation] Starting hourly weather update pipeline...")
    try:
        # Step 1: Fetch fresh synoptic data from Open-Meteo
        subprocess.run(["python", "open_meteo.py"], check=True)
        
        # Step 2: Run spatial inference grid to update predictions CSVs
        subprocess.run(["python", "predict_grid.py"], check=True)
        
        print("[Automation] Hourly pipeline completed successfully. Prediction CSVs updated.")
    except Exception as e:
        print(f"[Automation Error] Pipeline failed: {e}")

if __name__ == "__main__":
    scheduler = BackgroundScheduler()
    # Trigger every 1 hour
    scheduler.add_job(run_weather_pipeline, 'interval', hours=1)
    scheduler.start()
    
    print("SūkṣmaVṛṣṭi Hourly Automation Scheduler is running...")
    
    # Keep the script alive
    try:
        while True:
            time.sleep(60)
    except (KeyboardInterrupt, SystemExit):
        scheduler.shutdown()
        print("Scheduler shut down.")