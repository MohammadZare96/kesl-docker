import json
import logging
import service_util
import sqlite3 as sql
from pathlib import Path

CREATE_DB_REQUEST = '''
    CREATE TABLE IF NOT EXISTS scans(
        guid         TEXT PRIMARY KEY,
        status       TEXT,
        created      DATE,
        completed    DATE,
        progress     INTEGER,
        scan_params  TEXT,
        scan_errors  TEXT,
        scan_result  TEXT,
        scan_session TEXT
    );
'''


class ScansStorage:

    def __init__(self):
        self.conn = None
        self.path = None
        self.path_uri = None
        self.slog = logging.getLogger('main.db_conn')

    def final_construct(self, database_path):
        self.path = Path(database_path)
        self.path_uri = '{}?mode=rwc'.format(self.path.as_uri())

    def create_database(self):
        self.slog.debug(f'database not found. try to create {self.path_uri}')
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sql.connect(self.path_uri, uri=True, check_same_thread=False)
        with conn:
            cursor = conn.cursor()
            cursor.execute(CREATE_DB_REQUEST)
        return conn

    def connect(self):
        try:
            self.slog.debug(f'try to establish connection with {self.path_uri}')
            self.conn = sql.connect(self.path_uri, uri=True, check_same_thread=False) if self.path.exists() \
                else self.create_database()
            self.slog.debug(f'connection with {self.path_uri} established')
            return 'success', 0
        except sql.OperationalError as e:
            return f'unable to construct database with operation error {str(e)}', -1
        except (OSError, ValueError) as e:
            return f'unable to construct database with exception {str(e)}', -1

    def execute_request(self, request, data=None):
        try:
            if self.conn:
                with self.conn as conn:
                    cursor = conn.cursor()
                    cursor.execute(request, data) if data else cursor.execute(request)
                    conn.commit()
                    return cursor.fetchall(), 0
            else:
                print(f'unable to request to database because connection not established')
        except sql.IntegrityError as e:
            self.slog.error(f'SQL IntegrityError exception: {str(e)}')
            return str(e), -1
        except sql.OperationalError as e:
            self.slog.error(f'SQL OperationalError exception: {str(e)}')
            return str(e), -1
        except Exception as e:
            self.slog.error(f'SQL other exception: {str(e)}')
            return str(e), -1

    def add_record(self, scan_guid, scan_session):
        request = """ \
            INSERT INTO scans(guid, status, created, completed, progress, scan_params,
            scan_errors, scan_result, scan_session) \
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        data_tuple = (
            scan_guid, scan_session['scan_summary']['status'], scan_session['scan_summary']['created'],
            scan_session['scan_summary']['completed'], scan_session['scan_summary']['progress'],
            json.dumps(scan_session['scan_summary']['scan_params'], indent=4, default=service_util.json_default_decode),
            json.dumps(scan_session['scan_summary']['scan_errors'], indent=4, default=service_util.json_default_decode),
            json.dumps(scan_session['scan_summary']['scan_result'], indent=4, default=service_util.json_default_decode),
            json.dumps(scan_session['session_info'], indent=4, default=service_util.json_default_decode))
        response, app_code = self.execute_request(request, data_tuple)
        self.slog.debug(f'add new scan with guid {scan_guid} result: {app_code}')
        return response, app_code

    @staticmethod
    def service_convert(item, data):
        try:
            tmp = json.dumps(item[data], indent=4, default=service_util.json_default_decode)
            return tmp
        except (KeyError, ValueError):
            return None

    def db_full_update(self, scan_guid, scan_session):
        request = """ \
            UPDATE scans SET status = ?, created = ?, completed = ?, progress = ?, scan_params = ?,
            scan_errors = ?, scan_result = ?, scan_session = ? WHERE guid = ?
        """
        data_tuple = (
            scan_session['scan_summary']['status'], scan_session['scan_summary']['created'],
            scan_session['scan_summary']['completed'], scan_session['scan_summary']['progress'],
            self.service_convert(scan_session['scan_summary'], 'scan_params'),
            self.service_convert(scan_session['scan_summary'], 'scan_errors'),
            self.service_convert(scan_session['scan_summary'], 'scan_result'),
            json.dumps(scan_session['session_info'], indent=4, default=service_util.json_default_decode),
            scan_guid)
        response, app_code = self.execute_request(request, data_tuple)
        return response, app_code

    def db_get_records(self):
        request = """ SELECT * FROM scans """
        response, code = self.execute_request(request)
        return response, code
