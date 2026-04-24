import mysql.connector
from datetime import datetime
from app.config import Config
from app.utils.helpers import extract_project_user

def db_conn():
    """
    Establish and return a connection to the MySQL database 
    using configurations defined in app.config.Config.
    """
    return mysql.connector.connect(**Config.DB)

def ensure_db_schema():
    """
    Initialize the database schema if it does not already exist.
    Creates 'users' and 'scans' tables required for the dashboard.
    """
    conn = db_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username VARCHAR(255) PRIMARY KEY
    )""")

    cur.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255),
        project_name VARCHAR(255),
        total_issues INT DEFAULT 0,
        code_smells INT DEFAULT 0,
        vulnerabilities INT DEFAULT 0,
        code_coverage FLOAT DEFAULT 0,
        scan_date DATETIME DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_project_name (project_name),
        INDEX idx_username (username)
    )""")

    conn.commit()
    cur.close()
    conn.close()

def save_data(project_key, metrics, quality, ratings, issues):
    """
    Save or update the latest SonarQube scan metrics for a specific project 
    into the local database. If a scan already exists for today, it updates the existing record.
    
    Args:
        project_key (str): The unique identifier of the project.
        metrics (dict): Dictionary of raw metrics fetched from SonarQube.
        quality (str): Quality gate status (e.g., 'OK', 'ERROR').
        ratings (dict): Dictionary of reliability, security, and maintainability ratings.
        issues (list): List of issues fetched from SonarQube (unused in this function, but kept for signature).
    """
    conn = db_conn()
    cur = conn.cursor()

    # Extract username using the helper function
    username, _ = extract_project_user(project_key, project_key)

    cur.execute("INSERT IGNORE INTO users (username) VALUES (%s)", (username,))

    scan_date = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
    today_date = datetime.utcnow().strftime('%Y-%m-%d')
    bugs = metrics.get("bugs", 0)
    code_smells = metrics.get("code_smells", 0)
    vulnerabilities = metrics.get("vulnerabilities", 0)
    total_issues = bugs + code_smells + vulnerabilities
    coverage = metrics.get("coverage", 0)

    # Check if a scan already exists for this project today
    cur.execute(
        "SELECT id FROM scans WHERE project_name = %s AND DATE(scan_date) = %s LIMIT 1",
        (project_key, today_date)
    )
    existing_scan = cur.fetchone()

    if existing_scan:
        cur.execute("""
        UPDATE scans SET 
            total_issues = %s, code_smells = %s, vulnerabilities = %s, code_coverage = %s, scan_date = %s
        WHERE id = %s
        """, (total_issues, code_smells, vulnerabilities, coverage, scan_date, existing_scan[0]))
    else:
        cur.execute("""
        INSERT INTO scans (
            username, project_name, total_issues, code_smells, 
            vulnerabilities, code_coverage, scan_date
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            username, project_key, total_issues, code_smells, vulnerabilities, coverage, scan_date
        ))

    conn.commit()
    cur.close()
    conn.close()

def fetch_issues_from_db(project_key, issue_type=None, severity=None):
    """
    Retrieve issues for a given project from the local database (if issues are cached locally).
    Supports optional filtering by issue type and severity.
    
    Args:
        project_key (str): The unique identifier of the project.
        issue_type (str, optional): The type of issue to filter by (e.g., 'BUG', 'VULNERABILITY').
        severity (str, optional): The severity level to filter by (e.g., 'BLOCKER', 'CRITICAL').
        
    Returns:
        list[dict]: A list of dictionary objects representing the matching issues.
    """
    conn = db_conn()
    cur = conn.cursor(dictionary=True)
    query = "SELECT * FROM issues WHERE project_key = %s"
    params = [project_key]

    if issue_type and issue_type.upper() != 'ALL':
        query += " AND TRIM(UPPER(`type`)) = %s"
        params.append(issue_type.upper())

    if severity:
        query += " AND TRIM(UPPER(`severity`)) = %s"
        params.append(severity.upper())

    query += " ORDER BY severity DESC"
    cur.execute(query, tuple(params))
    issues = cur.fetchall()
    cur.close()
    conn.close()
    return issues
