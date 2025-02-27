from apscheduler.schedulers.background import BackgroundScheduler
from datetime import datetime, timedelta
from flask import Flask
import atexit
from .api import api_bp, calculate_sigma_mu_and_prove
from .storage import files_details_dict


def create_app():
    app = Flask(__name__)

    # Register the API Blueprint for the StorageServer app
    app.register_blueprint(api_bp)

    # Initialize the scheduler
    scheduler = BackgroundScheduler()

    # Function to check the files and trigger the handle function
    def check_files_to_validate():
        print("yay1")

        for filename, file_details in files_details_dict.items():
            validate_every = file_details.get("validate_every")
            last_verify = file_details.get("last_verify")

            print(last_verify, timedelta(seconds=validate_every), last_verify + timedelta(seconds=validate_every), datetime.now(), last_verify + timedelta(seconds=validate_every) < datetime.now())
            if last_verify + timedelta(seconds=validate_every) < datetime.now():
                print("yay2")
                is_proved: bool = calculate_sigma_mu_and_prove(filename, file_details.get("escrow_public_key"))
                if is_proved:
                    file_details["last_verify"] = datetime.now()

    # Add job to scheduler to run check_files_to_validate every minute
    scheduler.add_job(check_files_to_validate, 'interval', seconds=5)

    # Start the scheduler
    scheduler.start()

    # Graceful shutdown for the scheduler when the app stops
    def shutdown_scheduler():
        scheduler.shutdown()

    atexit.register(shutdown_scheduler)

    return app