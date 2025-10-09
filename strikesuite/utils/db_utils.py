#!/usr/bin/env python3
"""
Database Utilities
Database management and operations
"""

import sqlite3
import json
import logging
from typing import Dict, List, Optional, Any
from pathlib import Path

class DatabaseUtils:
    """
    Database utility functions
    """
    
    def __init__(self, db_path: str = "database/strikesuite.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.connection = None
    
    def connect(self) -> bool:
        """
        Connect to database
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure database directory exists
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            
            self.connection = sqlite3.connect(self.db_path)
            self.connection.row_factory = sqlite3.Row
            self.logger.info(f"Connected to database: {self.db_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to connect to database: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from database"""
        if self.connection:
            self.connection.close()
            self.connection = None
            self.logger.info("Disconnected from database")
    
    def initialize_database(self) -> bool:
        """
        Initialize database with required tables
        
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.connect():
                return False
            
            cursor = self.connection.cursor()
            
            # Create scan_history table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT,
                    status TEXT NOT NULL,
                    results TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create vulnerabilities table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    target TEXT NOT NULL,
                    vulnerability_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    recommendation TEXT,
                    evidence TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_history (id)
                )
            ''')
            
            # Create credentials table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    target TEXT NOT NULL,
                    service TEXT NOT NULL,
                    username TEXT NOT NULL,
                    password TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_history (id)
                )
            ''')
            
            # Create settings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create plugins table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS plugins (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    version TEXT NOT NULL,
                    description TEXT,
                    author TEXT,
                    category TEXT,
                    enabled BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create advanced scan results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS advanced_scan_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER,
                    scan_type TEXT NOT NULL,
                    target TEXT NOT NULL,
                    technique TEXT NOT NULL,
                    result_data TEXT,
                    confidence_score REAL,
                    false_positive BOOLEAN DEFAULT 0,
                    verified BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (scan_id) REFERENCES scan_history (id)
                )
            ''')
            
            # Create threat intelligence table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator TEXT UNIQUE NOT NULL,
                    indicator_type TEXT NOT NULL,
                    threat_level TEXT NOT NULL,
                    source TEXT,
                    description TEXT,
                    first_seen TIMESTAMP,
                    last_seen TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create behavioral patterns table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS behavioral_patterns (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    pattern_type TEXT NOT NULL,
                    pattern_data TEXT,
                    confidence REAL,
                    frequency INTEGER DEFAULT 1,
                    first_detected TIMESTAMP,
                    last_detected TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create CVE table for CVE training system
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cves (
                    id TEXT PRIMARY KEY,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    cvss_vector TEXT,
                    published_date TEXT,
                    modified_date TEXT,
                    cve_references TEXT,
                    products TEXT,
                    vendors TEXT,
                    attack_vector TEXT,
                    attack_complexity TEXT,
                    privileges_required TEXT,
                    user_interaction TEXT,
                    scope TEXT,
                    confidentiality_impact TEXT,
                    integrity_impact TEXT,
                    availability_impact TEXT,
                    exploitability_score REAL,
                    impact_score REAL,
                    category TEXT,
                    tags TEXT
                )
            ''')
            
            # Create training progress table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS training_progress (
                    user_id TEXT,
                    module_id TEXT,
                    completion_date TEXT,
                    score REAL,
                    attempts INTEGER,
                    PRIMARY KEY (user_id, module_id)
                )
            ''')
            
            # Create quiz results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS quiz_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT,
                    quiz_id TEXT,
                    score REAL,
                    total_questions INTEGER,
                    correct_answers INTEGER,
                    completion_date TEXT,
                    time_taken INTEGER
                )
            ''')
            
            self.connection.commit()
            self.logger.info("Database initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize database: {e}")
            return False
        finally:
            self.disconnect()
    
    def save_scan_result(self, scan_type: str, target: str, results: Dict) -> Optional[int]:
        """
        Save scan results to database
        
        Args:
            scan_type: Type of scan
            target: Target scanned
            results: Scan results
            
        Returns:
            Scan ID or None if failed
        """
        try:
            if not self.connect():
                return None
            
            cursor = self.connection.cursor()
            
            # Insert scan record
            cursor.execute('''
                INSERT INTO scan_history (scan_type, target, start_time, end_time, status, results)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                scan_type,
                target,
                results.get('start_time', ''),
                results.get('end_time', ''),
                results.get('status', 'completed'),
                json.dumps(results)
            ))
            
            scan_id = cursor.lastrowid
            
            # Save vulnerabilities
            if 'vulnerabilities' in results:
                for vuln in results['vulnerabilities']:
                    cursor.execute('''
                        INSERT INTO vulnerabilities (scan_id, target, vulnerability_type, severity, description, recommendation, evidence)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        scan_id,
                        target,
                        vuln.get('type', ''),
                        vuln.get('severity', ''),
                        vuln.get('description', ''),
                        vuln.get('recommendation', ''),
                        vuln.get('evidence', '')
                    ))
            
            # Save credentials
            if 'credentials' in results:
                for cred in results['credentials']:
                    cursor.execute('''
                        INSERT INTO credentials (scan_id, target, service, username, password)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (
                        scan_id,
                        target,
                        cred.get('service', ''),
                        cred.get('username', ''),
                        cred.get('password', '')
                    ))
            
            self.connection.commit()
            self.logger.info(f"Saved scan result with ID: {scan_id}")
            return scan_id
            
        except Exception as e:
            self.logger.error(f"Failed to save scan result: {e}")
            return None
        finally:
            self.disconnect()
    
    def get_scan_history(self, limit: int = 100) -> List[Dict]:
        """
        Get scan history
        
        Args:
            limit: Maximum number of records
            
        Returns:
            List of scan records
        """
        try:
            if not self.connect():
                return []
            
            cursor = self.connection.cursor()
            cursor.execute('''
                SELECT * FROM scan_history 
                ORDER BY created_at DESC 
                LIMIT ?
            ''', (limit,))
            
            records = []
            for row in cursor.fetchall():
                record = dict(row)
                if record['results']:
                    record['results'] = json.loads(record['results'])
                records.append(record)
            
            return records
            
        except Exception as e:
            self.logger.error(f"Failed to get scan history: {e}")
            return []
        finally:
            self.disconnect()
    
    def get_vulnerabilities(self, scan_id: Optional[int] = None) -> List[Dict]:
        """
        Get vulnerabilities
        
        Args:
            scan_id: Specific scan ID (optional)
            
        Returns:
            List of vulnerability records
        """
        try:
            if not self.connect():
                return []
            
            cursor = self.connection.cursor()
            
            if scan_id:
                cursor.execute('''
                    SELECT * FROM vulnerabilities 
                    WHERE scan_id = ?
                    ORDER BY created_at DESC
                ''', (scan_id,))
            else:
                cursor.execute('''
                    SELECT * FROM vulnerabilities 
                    ORDER BY created_at DESC
                ''')
            
            records = []
            for row in cursor.fetchall():
                records.append(dict(row))
            
            return records
            
        except Exception as e:
            self.logger.error(f"Failed to get vulnerabilities: {e}")
            return []
        finally:
            self.disconnect()
    
    def get_credentials(self, scan_id: Optional[int] = None) -> List[Dict]:
        """
        Get credentials
        
        Args:
            scan_id: Specific scan ID (optional)
            
        Returns:
            List of credential records
        """
        try:
            if not self.connect():
                return []
            
            cursor = self.connection.cursor()
            
            if scan_id:
                cursor.execute('''
                    SELECT * FROM credentials 
                    WHERE scan_id = ?
                    ORDER BY created_at DESC
                ''', (scan_id,))
            else:
                cursor.execute('''
                    SELECT * FROM credentials 
                    ORDER BY created_at DESC
                ''')
            
            records = []
            for row in cursor.fetchall():
                records.append(dict(row))
            
            return records
            
        except Exception as e:
            self.logger.error(f"Failed to get credentials: {e}")
            return []
        finally:
            self.disconnect()
    
    def save_setting(self, key: str, value: str) -> bool:
        """
        Save application setting
        
        Args:
            key: Setting key
            value: Setting value
            
        Returns:
            True if successful, False otherwise
        """
        try:
            if not self.connect():
                return False
            
            cursor = self.connection.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO settings (key, value, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (key, value))
            
            self.connection.commit()
            self.logger.info(f"Saved setting: {key}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save setting: {e}")
            return False
        finally:
            self.disconnect()
    
    def get_setting(self, key: str, default: str = None) -> Optional[str]:
        """
        Get application setting
        
        Args:
            key: Setting key
            default: Default value if not found
            
        Returns:
            Setting value or default
        """
        try:
            if not self.connect():
                return default
            
            cursor = self.connection.cursor()
            cursor.execute('SELECT value FROM settings WHERE key = ?', (key,))
            
            row = cursor.fetchone()
            if row:
                return row['value']
            return default
            
        except Exception as e:
            self.logger.error(f"Failed to get setting: {e}")
            return default
        finally:
            self.disconnect()
    
    def cleanup_old_data(self, days: int = 30) -> int:
        """
        Clean up old scan data
        
        Args:
            days: Number of days to keep data
            
        Returns:
            Number of records deleted
        """
        try:
            if not self.connect():
                return 0
            
            cursor = self.connection.cursor()
            
            # Delete old scan history
            cursor.execute('''
                DELETE FROM scan_history 
                WHERE created_at < datetime('now', '-{} days')
            '''.format(days))
            
            deleted_count = cursor.rowcount
            
            # Clean up orphaned records
            cursor.execute('''
                DELETE FROM vulnerabilities 
                WHERE scan_id NOT IN (SELECT id FROM scan_history)
            ''')
            
            cursor.execute('''
                DELETE FROM credentials 
                WHERE scan_id NOT IN (SELECT id FROM scan_history)
            ''')
            
            self.connection.commit()
            self.logger.info(f"Cleaned up {deleted_count} old records")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Failed to cleanup old data: {e}")
            return 0
        finally:
            self.disconnect()

# Global database manager instance
db_manager = DatabaseUtils()

def init_db():
    """Initialize database - global function for compatibility"""
    return db_manager.initialize_database()

def get_db_manager():
    """Get database manager instance"""
    return db_manager

def get_scan_history(limit: int = 100) -> List[Dict]:
    """Get scan history - global function for compatibility"""
    return db_manager.get_scan_history(limit)

def get_vulnerability_data(scan_id: Optional[int] = None) -> List[Dict]:
    """Get vulnerability data - global function for compatibility"""
    return db_manager.get_vulnerabilities(scan_id)