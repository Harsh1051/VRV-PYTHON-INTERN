Log Analysis System
Overview
An advanced log analysis tool designed to process web server logs, uncover usage patterns, detect potential security risks, and provide actionable insights. The system produces both CSV and HTML reports to facilitate easy data interpretation and visualization.

Key Features
IP Traffic Insights: Monitors and summarizes the request volume for each IP address.
Endpoint Analysis: Highlights the most frequently visited endpoints.
Security Monitoring: Identifies suspicious behavior, such as repeated failed login attempts.
Multiple Report Formats:
Interactive HTML reports with sortable and user-friendly tables
CSV files for seamless integration with external tools
Real-time terminal output for instant data review
Technical Implementation
Developed in Python, leveraging core libraries to minimize external dependencies.
Utilizes collections.Counter for efficient data aggregation.
Employs regular expressions for precise log file parsing.
Generates visually appealing and responsive HTML reports using modern CSS.
Sample Output
The tool provides three primary insights:

IP Request Summary: Displays traffic distribution by IP.
Endpoint Popularity: Lists the URLs or endpoints that receive the most traffic.
Security Alerts: Flags potentially harmful activities, such as repeated failed login attempts from specific IPs.
Setup and Installation
Prerequisites
Python 3.6 or newer
Optional: Git for cloning the repository
Installation
Clone the repository or download the script.
Install necessary dependencies:
bash
Copy code
pip install prettytable
How to Use
Input
The tool works with web server logs in the standard Apache or Nginx format.
A sample log file (sample.log) is provided for testing purposes.
You can replace sample.log with your own log file in a similar format.
Processing
Place the log file in the project folder.
Execute the script using the command below:
bash
Copy code
python log_analysis.py
The script processes the log file and performs:
Analysis of request frequency by IP
Identification of popular endpoints
Detection of suspicious activity
Output Options
HTML Report:

Open log_analysis_report.html in your preferred web browser.
Alternatively, use the terminal command start log_analysis_report.html to open it.
CSV Report:

Data is saved in log_analysis_results.csv for further analysis or spreadsheet manipulation.
Terminal View:

Key insights are displayed directly in the terminal for a quick summary.
