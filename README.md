# Network Monitoring Application

## Overview

This project is a network monitoring application that uses SNMP (Simple Network Management Protocol) to gather data from network devices and display it on a web interface.

## Components

- `app.py`: A Flask-based web application that serves the frontend and interacts with the database.
- `main.py`: A Python script for gathering network data using SNMP.
- `index.html`: The frontend of the application, displaying system information and network traffic data.

## Features

- Display of real-time network monitoring data.
- Visualization of traffic data using Chart.js.

## Setup and Installation

- Ensure Python and Flask are installed.
- Install dependencies: `pysnmp`, `flask_sqlalchemy`, etc.
- Configure database settings in `app.py`.
- Set target device information in `main.py`.

## Usage

1. Run `app.py` to start the Flask server.
2. Access the web interface via the provided URL (typically `localhost` on a specified port).
3. Monitor real-time data on network performance and system info.

## Dependencies

- Flask
- pysnmp
- Chart.js (loaded via CDN in `index.html`)

## Contribution

Feel free to contribute to this project by submitting pull requests or opening issues for bugs and feature requests.
