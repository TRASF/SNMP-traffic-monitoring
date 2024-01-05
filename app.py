from flask import Flask, render_template, jsonify
import main as main
import threading
from flask_sqlalchemy import SQLAlchemy
import json
import schedule
import time
import requests

app = Flask(__name__)

app.config[
    "SQLALCHEMY_DATABASE_URI"
] = "postgresql://postgres:password@localhost/netdb"  # Update with your credentials
db = SQLAlchemy(app)


class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(80), unique=True, nullable=False)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    traffic_data = db.Column(db.String(5000))


class SystemInfo(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    sys_descr = db.Column(db.String)
    sys_object_id = db.Column(db.String)
    sys_uptime = db.Column(db.String)
    sys_contact = db.Column(db.String)
    sys_name = db.Column(db.String)
    sys_location = db.Column(db.String)
    sys_services = db.Column(db.String)


class TcpConnection(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=db.func.current_timestamp())
    tcp_conn_state = db.Column(db.String)
    tcp_conn_local_address = db.Column(db.String)
    tcp_conn_local_port = db.Column(db.Integer)
    tcp_conn_rem_address = db.Column(db.String)
    tcp_conn_rem_port = db.Column(db.Integer)


with app.app_context():
    db.create_all()


def process_tcp_data(raw_data, target_ip):
    processed_data = []
    for oid, value in raw_data.items():
        parts = oid.split(".")

        if len(parts) >= 10:
            ip_address = ".".join(parts[-10:-6])
            port = int(parts[-5])

            # Check if the IP address matches the target IP address
            if ip_address == target_ip:
                conn_dict = {
                    "tcp_conn_state": value,
                    "tcp_conn_local_address": ip_address,
                    "tcp_conn_local_port": port,
                    "tcp_conn_rem_address": "Unknown",
                    "tcp_conn_rem_port": 0,
                }
                processed_data.append(conn_dict)

    return processed_data


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/get_traffic_data")
def get_traffic_data():
    try:
        # Fetch traffic data
        traffic_data = main.fetch_traffic_data(main.target, main.community)
        return jsonify(traffic_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/get_system_data")
def get_system_data():
    try:
        # Fetch system data
        system_data = main.fetch_system(main.target, main.community)
        return jsonify(system_data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/fetch_data")
def get_data():
    try:
        print("Fetching data...")
        traffic_data = main.fetch_traffic_data(main.target, main.community)
        traffic_data_str = json.dumps(traffic_data)

        # Check if a record with the same hostname already exists
        log_entry = Log.query.filter_by(hostname=main.target).first()

        if log_entry:
            # Update existing record
            log_entry.traffic_data = traffic_data_str
        else:
            # Create a new record
            log_entry = Log(hostname=main.target, traffic_data=traffic_data_str)
            db.session.add(log_entry)

        # Fetch system and TCP connection data
        detailed_data = main.fetch_system_and_tcp_data(main.target, main.community)

        # Process and store system data
        system_info = detailed_data.get("system_data", {})
        unique_id = system_info.get(
            "SNMPv2-MIB::sysName.0"
        )  # Use sysName as unique identifier

        if unique_id:
            system_entry = SystemInfo.query.filter_by(sys_name=unique_id).first()
            if system_entry:
                # Update existing record
                system_entry.sys_descr = system_info.get("SNMPv2-MIB::sysDescr.0")
                system_entry.sys_uptime = system_info.get("SNMPv2-MIB::sysUpTime.0")
                system_entry.sys_contact = system_info.get("SNMPv2-MIB::sysContact.0")
            else:
                # Create a new record
                new_system_entry = SystemInfo(
                    sys_name=unique_id,
                    sys_descr=system_info.get("SNMPv2-MIB::sysDescr.0"),
                    sys_uptime=system_info.get("SNMPv2-MIB::sysUpTime.0"),
                    sys_contact=system_info.get("SNMPv2-MIB::sysContact.0"),
                )
                db.session.add(new_system_entry)

        # Process and store TCP connection data
        if detailed_data.get("tcp_connection_table"):
            target_ip = "192.168.1.8"  # Replace with the actual target IP address
            raw_tcp_data = detailed_data["tcp_connection_table"]
            tcp_connection_data = process_tcp_data(raw_tcp_data, target_ip)

            for tcp_connection in tcp_connection_data:
                tcp_entry = TcpConnection(**tcp_connection)
                db.session.add(tcp_entry)

        db.session.commit()
        return jsonify({"message": "Data fetched and stored successfully"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500


def background_task():
    # Wait for a short period to ensure the Flask server is up
    time.sleep(5)  # Wait for 5 seconds before starting the periodic tasks
    while True:
        try:
            response = requests.get("http://127.0.0.1:5000/fetch_data")
            if response.status_code == 200:
                print("Data fetched successfully.")
            else:
                print("Error fetching data:", response.json())
        except Exception as e:
            print("Error in background task:", e)
        time.sleep(60)  # Wait for 1 minute before the next request


def start_background_thread():
    schedule.every(1).minutes.do(background_task)
    background_thread = threading.Thread(target=background_task, daemon=True)
    background_thread.start()


if __name__ == "__main__":
    start_background_thread()
    app.run(debug=True, use_reloader=False)
