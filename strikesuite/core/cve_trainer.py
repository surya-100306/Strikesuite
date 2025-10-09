#!/usr/bin/env python3
"""
CVE Training System
Comprehensive CVE database, training modules, and educational features
"""

import json
import sqlite3
import requests
import time
import hashlib
import random
from typing import Dict, List, Tuple, Optional
from datetime import datetime, timedelta
import logging
from pathlib import Path
import re
import csv
import xml.etree.ElementTree as ET

class CVETrainer:
    """
    Comprehensive CVE Training System with database, modules, and educational features
    """
    
    def __init__(self, db_path: str = "database/strikesuite.db"):
        self.db_path = db_path
        self.logger = logging.getLogger(__name__)
        self.cve_database = {}
        self.training_modules = {}
        self.quiz_questions = {}
        self.vulnerability_patterns = {}
        
        # Initialize database
        self._init_database()
        
        # Load CVE data
        self._load_cve_data()
        
        # Initialize training modules
        self._init_training_modules()
        
        # Initialize quiz system
        self._init_quiz_system()
    
    def _init_database(self):
        """Initialize SQLite database for CVE storage"""
        try:
            # Use the main database utilities to ensure tables are created
            from utils.db_utils import init_db
            init_db()
            
        except Exception as e:
            self.logger.error(f"Database initialization error: {e}")
    
    def _load_cve_data(self):
        """Load CVE data from various sources"""
        try:
            # Load built-in CVE data
            self._load_builtin_cves()
            
            # Load from NVD if available
            self._load_nvd_data()
            
            # Load custom CVE data
            self._load_custom_cves()
            
        except Exception as e:
            self.logger.error(f"Error loading CVE data: {e}")
    
    def _load_builtin_cves(self):
        """Load built-in CVE database with common vulnerabilities"""
        builtin_cves = {
            "CVE-2014-0160": {
                "description": "The TLS and DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets, which allows remote attackers to obtain sensitive information from process memory via crafted packets that trigger a buffer over-read.",
                "severity": "Critical",
                "cvss_score": 7.5,
                "cvss_vector": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "published_date": "2014-04-07",
                "category": "Cryptographic",
                "tags": ["heartbleed", "openssl", "tls", "dtls", "memory-disclosure"],
                "products": ["OpenSSL"],
                "vendors": ["OpenSSL Software Foundation"],
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "None",
                "scope": "Unchanged",
                "confidentiality_impact": "High",
                "integrity_impact": "None",
                "availability_impact": "None"
            },
            "CVE-2017-0144": {
                "description": "The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1; and Windows 10 Gold, 1511, 1607, 1703, and Windows Server 2016 allows remote attackers to execute arbitrary code via crafted packets.",
                "severity": "Critical",
                "cvss_score": 9.3,
                "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "published_date": "2017-03-14",
                "category": "Remote Code Execution",
                "tags": ["eternalblue", "smb", "windows", "wannacry", "ransomware"],
                "products": ["Windows"],
                "vendors": ["Microsoft"],
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "None",
                "scope": "Unchanged",
                "confidentiality_impact": "Complete",
                "integrity_impact": "Complete",
                "availability_impact": "Complete"
            },
            "CVE-2021-44228": {
                "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.17.0) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints.",
                "severity": "Critical",
                "cvss_score": 10.0,
                "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "published_date": "2021-12-09",
                "category": "Remote Code Execution",
                "tags": ["log4shell", "log4j", "jndi", "ldap", "rce"],
                "products": ["Apache Log4j"],
                "vendors": ["Apache Software Foundation"],
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "None",
                "scope": "Unchanged",
                "confidentiality_impact": "Complete",
                "integrity_impact": "Complete",
                "availability_impact": "Complete"
            },
            "CVE-2014-6271": {
                "description": "GNU Bash through 4.3 processes trailing strings after function definitions in the values of environment variables, which allows remote attackers to execute arbitrary code via a crafted environment.",
                "severity": "Critical",
                "cvss_score": 9.8,
                "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "published_date": "2014-09-24",
                "category": "Remote Code Execution",
                "tags": ["shellshock", "bash", "environment-variables", "rce"],
                "products": ["GNU Bash"],
                "vendors": ["GNU"],
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "None",
                "scope": "Unchanged",
                "confidentiality_impact": "Complete",
                "integrity_impact": "Complete",
                "availability_impact": "Complete"
            },
            "CVE-2017-5638": {
                "description": "The Jakarta Multipart parser in Apache Struts 2 2.3.x before 2.3.34 and 2.5.x before 2.5.10.1 mishandles file upload, which allows remote attackers to execute arbitrary commands via a crafted Content-Type, Content-Disposition, or Content-Length HTTP header.",
                "severity": "Critical",
                "cvss_score": 10.0,
                "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                "published_date": "2017-03-07",
                "category": "Remote Code Execution",
                "tags": ["struts", "file-upload", "ognl", "rce"],
                "products": ["Apache Struts"],
                "vendors": ["Apache Software Foundation"],
                "attack_vector": "Network",
                "attack_complexity": "Low",
                "privileges_required": "None",
                "user_interaction": "None",
                "scope": "Unchanged",
                "confidentiality_impact": "Complete",
                "integrity_impact": "Complete",
                "availability_impact": "Complete"
            }
        }
        
        self.cve_database.update(builtin_cves)
        self._save_cves_to_db(builtin_cves)
    
    def _load_nvd_data(self):
        """Load CVE data from NVD (National Vulnerability Database)"""
        try:
            # This would typically fetch from NVD API
            # For demo purposes, we'll simulate some additional CVEs
            nvd_cves = {
                "CVE-2020-1472": {
                    "description": "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller.",
                    "severity": "Critical",
                    "cvss_score": 10.0,
                    "cvss_vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                    "published_date": "2020-08-11",
                    "category": "Privilege Escalation",
                    "tags": ["zerologon", "netlogon", "windows", "domain-controller"],
                    "products": ["Windows Server"],
                    "vendors": ["Microsoft"]
                }
            }
            
            self.cve_database.update(nvd_cves)
            self._save_cves_to_db(nvd_cves)
            
        except Exception as e:
            self.logger.error(f"Error loading NVD data: {e}")
    
    def _load_custom_cves(self):
        """Load custom CVE data from local files"""
        try:
            custom_cve_file = Path("data/custom_cves.json")
            if custom_cve_file.exists():
                with open(custom_cve_file, 'r') as f:
                    custom_cves = json.load(f)
                    self.cve_database.update(custom_cves)
                    self._save_cves_to_db(custom_cves)
        except Exception as e:
            self.logger.error(f"Error loading custom CVE data: {e}")
    
    def _save_cves_to_db(self, cves: Dict):
        """Save CVE data to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for cve_id, cve_data in cves.items():
                cursor.execute('''
                    INSERT OR REPLACE INTO cves (
                        id, description, severity, cvss_score, cvss_vector,
                        published_date, category, tags, products, vendors,
                        attack_vector, attack_complexity, privileges_required,
                        user_interaction, scope, confidentiality_impact,
                        integrity_impact, availability_impact
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    cve_id,
                    cve_data.get('description', ''),
                    cve_data.get('severity', ''),
                    cve_data.get('cvss_score', 0.0),
                    cve_data.get('cvss_vector', ''),
                    cve_data.get('published_date', ''),
                    cve_data.get('category', ''),
                    json.dumps(cve_data.get('tags', [])),
                    json.dumps(cve_data.get('products', [])),
                    json.dumps(cve_data.get('vendors', [])),
                    cve_data.get('attack_vector', ''),
                    cve_data.get('attack_complexity', ''),
                    cve_data.get('privileges_required', ''),
                    cve_data.get('user_interaction', ''),
                    cve_data.get('scope', ''),
                    cve_data.get('confidentiality_impact', ''),
                    cve_data.get('integrity_impact', ''),
                    cve_data.get('availability_impact', '')
                ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error saving CVE data to database: {e}")
    
    def _init_training_modules(self):
        """Initialize CVE training modules"""
        self.training_modules = {
            "cve_basics": {
                "title": "CVE Fundamentals",
                "description": "Learn the basics of Common Vulnerabilities and Exposures",
                "duration": "30 minutes",
                "difficulty": "Beginner",
                "topics": [
                    "What is a CVE?",
                    "CVE numbering system",
                    "CVSS scoring",
                    "CVE lifecycle",
                    "CVE databases"
                ],
                "lessons": [
                    {
                        "title": "Introduction to CVEs",
                        "content": "Common Vulnerabilities and Exposures (CVE) is a dictionary of publicly known information security vulnerabilities and exposures.",
                        "quiz_questions": 3
                    },
                    {
                        "title": "CVE Numbering",
                        "content": "CVEs are assigned unique identifiers in the format CVE-YYYY-NNNN where YYYY is the year and NNNN is a sequence number.",
                        "quiz_questions": 2
                    }
                ]
            },
            "cvss_scoring": {
                "title": "CVSS Scoring System",
                "description": "Master the Common Vulnerability Scoring System",
                "duration": "45 minutes",
                "difficulty": "Intermediate",
                "topics": [
                    "CVSS v3.1 metrics",
                    "Base score calculation",
                    "Temporal metrics",
                    "Environmental metrics",
                    "Score interpretation"
                ],
                "lessons": [
                    {
                        "title": "CVSS Base Metrics",
                        "content": "CVSS base metrics include Attack Vector, Attack Complexity, Privileges Required, User Interaction, Scope, and Impact metrics.",
                        "quiz_questions": 4
                    }
                ]
            },
            "critical_cves": {
                "title": "Critical CVE Analysis",
                "description": "Study the most impactful vulnerabilities in history",
                "duration": "60 minutes",
                "difficulty": "Advanced",
                "topics": [
                    "Heartbleed (CVE-2014-0160)",
                    "EternalBlue (CVE-2017-0144)",
                    "Log4Shell (CVE-2021-44228)",
                    "Shellshock (CVE-2014-6271)",
                    "ZeroLogon (CVE-2020-1472)"
                ],
                "lessons": [
                    {
                        "title": "Heartbleed Analysis",
                        "content": "Heartbleed was a critical vulnerability in OpenSSL that allowed attackers to read memory from vulnerable servers.",
                        "quiz_questions": 5
                    }
                ]
            },
            "exploit_development": {
                "title": "Exploit Development",
                "description": "Learn how to develop exploits for known vulnerabilities",
                "duration": "90 minutes",
                "difficulty": "Expert",
                "topics": [
                    "Vulnerability research",
                    "Proof of concept development",
                    "Exploit techniques",
                    "Payload development",
                    "Exploit mitigation"
                ],
                "lessons": [
                    {
                        "title": "Exploit Development Process",
                        "content": "Exploit development involves vulnerability analysis, proof of concept creation, and payload development.",
                        "quiz_questions": 6
                    }
                ]
            }
        }
    
    def _init_quiz_system(self):
        """Initialize quiz questions for training modules"""
        self.quiz_questions = {
            "cve_basics": [
                {
                    "question": "What does CVE stand for?",
                    "options": [
                        "Common Vulnerabilities and Exposures",
                        "Critical Vulnerability Exploits",
                        "Computer Vulnerability Engine",
                        "Common Vulnerability Entries"
                    ],
                    "correct": 0,
                    "explanation": "CVE stands for Common Vulnerabilities and Exposures, a dictionary of publicly known security vulnerabilities."
                },
                {
                    "question": "What is the format of a CVE identifier?",
                    "options": [
                        "CVE-YYYY-NNNN",
                        "CVE-YYYY-NNNNN",
                        "CVE-YY-NNNN",
                        "CVE-YYYY-NNN"
                    ],
                    "correct": 0,
                    "explanation": "CVE identifiers follow the format CVE-YYYY-NNNN where YYYY is the year and NNNN is a sequence number."
                }
            ],
            "cvss_scoring": [
                {
                    "question": "What is the maximum CVSS v3.1 base score?",
                    "options": ["7.0", "8.0", "9.0", "10.0"],
                    "correct": 3,
                    "explanation": "The maximum CVSS v3.1 base score is 10.0, indicating the most severe vulnerabilities."
                },
                {
                    "question": "Which metric is NOT part of CVSS v3.1 base metrics?",
                    "options": [
                        "Attack Vector",
                        "Attack Complexity", 
                        "Privileges Required",
                        "Exploitability"
                    ],
                    "correct": 3,
                    "explanation": "Exploitability is not a base metric in CVSS v3.1. It's calculated from other base metrics."
                }
            ],
            "critical_cves": [
                {
                    "question": "Which CVE is known as 'Heartbleed'?",
                    "options": [
                        "CVE-2014-0160",
                        "CVE-2014-6271", 
                        "CVE-2017-0144",
                        "CVE-2021-44228"
                    ],
                    "correct": 0,
                    "explanation": "CVE-2014-0160 is the Heartbleed vulnerability in OpenSSL that allowed memory disclosure."
                },
                {
                    "question": "What was the primary impact of the EternalBlue vulnerability?",
                    "options": [
                        "Information disclosure",
                        "Denial of service",
                        "Remote code execution",
                        "Privilege escalation"
                    ],
                    "correct": 2,
                    "explanation": "EternalBlue (CVE-2017-0144) allowed remote code execution through SMB vulnerabilities."
                }
            ]
        }
    
    def get_cve_info(self, cve_id: str) -> Optional[Dict]:
        """Get detailed information about a specific CVE"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM cves WHERE id = ?', (cve_id,))
            row = cursor.fetchone()
            
            if row:
                columns = [description[0] for description in cursor.description]
                cve_data = dict(zip(columns, row))
                
                # Parse JSON fields
                cve_data['tags'] = json.loads(cve_data['tags']) if cve_data['tags'] else []
                cve_data['products'] = json.loads(cve_data['products']) if cve_data['products'] else []
                cve_data['vendors'] = json.loads(cve_data['vendors']) if cve_data['vendors'] else []
                
                conn.close()
                return cve_data
            
            conn.close()
            return None
            
        except Exception as e:
            self.logger.error(f"Error getting CVE info: {e}")
            return None
    
    def search_cves(self, query: str, filters: Dict = None) -> List[Dict]:
        """Search CVEs by query and filters"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build search query
            search_query = "SELECT * FROM cves WHERE 1=1"
            params = []
            
            if query:
                search_query += " AND (description LIKE ? OR id LIKE ? OR tags LIKE ?)"
                params.extend([f"%{query}%", f"%{query}%", f"%{query}%"])
            
            if filters:
                if filters.get('severity'):
                    search_query += " AND severity = ?"
                    params.append(filters['severity'])
                
                if filters.get('min_cvss'):
                    search_query += " AND cvss_score >= ?"
                    params.append(filters['min_cvss'])
                
                if filters.get('category'):
                    search_query += " AND category = ?"
                    params.append(filters['category'])
            
            cursor.execute(search_query, params)
            rows = cursor.fetchall()
            
            columns = [description[0] for description in cursor.description]
            results = []
            
            for row in rows:
                cve_data = dict(zip(columns, row))
                cve_data['tags'] = json.loads(cve_data['tags']) if cve_data['tags'] else []
                cve_data['products'] = json.loads(cve_data['products']) if cve_data['products'] else []
                cve_data['vendors'] = json.loads(cve_data['vendors']) if cve_data['vendors'] else []
                results.append(cve_data)
            
            conn.close()
            return results
            
        except Exception as e:
            self.logger.error(f"Error searching CVEs: {e}")
            return []
    
    def get_training_modules(self) -> Dict:
        """Get available training modules"""
        return self.training_modules
    
    def start_training_module(self, module_id: str, user_id: str = "default") -> Dict:
        """Start a training module"""
        if module_id not in self.training_modules:
            return {"error": "Module not found"}
        
        module = self.training_modules[module_id]
        return {
            "module_id": module_id,
            "title": module["title"],
            "description": module["description"],
            "duration": module["duration"],
            "difficulty": module["difficulty"],
            "topics": module["topics"],
            "lessons": module["lessons"],
            "user_id": user_id,
            "start_time": datetime.now().isoformat()
        }
    
    def get_quiz_questions(self, module_id: str) -> List[Dict]:
        """Get quiz questions for a training module"""
        return self.quiz_questions.get(module_id, [])
    
    def submit_quiz(self, module_id: str, answers: List[int], user_id: str = "default") -> Dict:
        """Submit quiz answers and get results"""
        questions = self.get_quiz_questions(module_id)
        
        if not questions:
            return {"error": "No questions found for this module"}
        
        if len(answers) != len(questions):
            return {"error": "Number of answers doesn't match number of questions"}
        
        correct_answers = 0
        results = []
        
        for i, (question, answer) in enumerate(zip(questions, answers)):
            is_correct = answer == question["correct"]
            if is_correct:
                correct_answers += 1
            
            results.append({
                "question": question["question"],
                "user_answer": answer,
                "correct_answer": question["correct"],
                "is_correct": is_correct,
                "explanation": question["explanation"]
            })
        
        score = (correct_answers / len(questions)) * 100
        
        # Save quiz results to database
        self._save_quiz_results(user_id, module_id, score, len(questions), correct_answers)
        
        return {
            "score": score,
            "total_questions": len(questions),
            "correct_answers": correct_answers,
            "results": results,
            "passed": score >= 70  # 70% passing grade
        }
    
    def _save_quiz_results(self, user_id: str, quiz_id: str, score: float, 
                          total_questions: int, correct_answers: int):
        """Save quiz results to database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO quiz_results 
                (user_id, quiz_id, score, total_questions, correct_answers, completion_date)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, quiz_id, score, total_questions, correct_answers, 
                  datetime.now().isoformat()))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error saving quiz results: {e}")
    
    def get_user_progress(self, user_id: str = "default") -> Dict:
        """Get user's training progress"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get quiz results
            cursor.execute('''
                SELECT quiz_id, score, completion_date, time_taken
                FROM quiz_results WHERE user_id = ?
                ORDER BY completion_date DESC
            ''', (user_id,))
            
            quiz_results = cursor.fetchall()
            
            # Get training progress
            cursor.execute('''
                SELECT module_id, completion_date, score, attempts
                FROM training_progress WHERE user_id = ?
            ''', (user_id,))
            
            training_progress = cursor.fetchall()
            
            conn.close()
            
            return {
                "user_id": user_id,
                "quiz_results": quiz_results,
                "training_progress": training_progress,
                "total_modules_completed": len(training_progress),
                "average_quiz_score": sum(r[1] for r in quiz_results) / len(quiz_results) if quiz_results else 0
            }
            
        except Exception as e:
            self.logger.error(f"Error getting user progress: {e}")
            return {"error": str(e)}
    
    def generate_cve_report(self, cve_ids: List[str]) -> Dict:
        """Generate a comprehensive CVE report"""
        report = {
            "generated_date": datetime.now().isoformat(),
            "total_cves": len(cve_ids),
            "severity_breakdown": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0},
            "cve_details": [],
            "recommendations": []
        }
        
        for cve_id in cve_ids:
            cve_info = self.get_cve_info(cve_id)
            if cve_info:
                report["cve_details"].append(cve_info)
                severity = cve_info.get("severity", "Unknown")
                if severity in report["severity_breakdown"]:
                    report["severity_breakdown"][severity] += 1
        
        # Generate recommendations based on CVEs
        report["recommendations"] = self._generate_recommendations(report["cve_details"])
        
        return report
    
    def _generate_recommendations(self, cves: List[Dict]) -> List[str]:
        """Generate security recommendations based on CVE analysis"""
        recommendations = []
        
        critical_count = sum(1 for cve in cves if cve.get("severity") == "Critical")
        if critical_count > 0:
            recommendations.append(f"🚨 IMMEDIATE ACTION REQUIRED: {critical_count} critical vulnerabilities found")
        
        high_count = sum(1 for cve in cves if cve.get("severity") == "High")
        if high_count > 0:
            recommendations.append(f"⚠️ HIGH PRIORITY: Address {high_count} high-severity vulnerabilities within 48 hours")
        
        # Check for specific vulnerability types
        categories = [cve.get("category", "") for cve in cves]
        if "Remote Code Execution" in categories:
            recommendations.append("🔧 Implement network segmentation and access controls for RCE vulnerabilities")
        
        if "Cryptographic" in categories:
            recommendations.append("🔐 Update cryptographic libraries and disable weak ciphers")
        
        return recommendations
    
    def get_cve_statistics(self) -> Dict:
        """Get CVE database statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Total CVEs
            cursor.execute('SELECT COUNT(*) FROM cves')
            total_cves = cursor.fetchone()[0]
            
            # Severity breakdown
            cursor.execute('SELECT severity, COUNT(*) FROM cves GROUP BY severity')
            severity_stats = dict(cursor.fetchall())
            
            # Category breakdown
            cursor.execute('SELECT category, COUNT(*) FROM cves GROUP BY category')
            category_stats = dict(cursor.fetchall())
            
            # Average CVSS score
            cursor.execute('SELECT AVG(cvss_score) FROM cves WHERE cvss_score > 0')
            avg_cvss = cursor.fetchone()[0] or 0
            
            conn.close()
            
            return {
                "total_cves": total_cves,
                "severity_breakdown": severity_stats,
                "category_breakdown": category_stats,
                "average_cvss_score": round(avg_cvss, 2),
                "database_last_updated": datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting CVE statistics: {e}")
            return {"error": str(e)}
    
    def get_all_cves(self, limit: int = None, offset: int = 0) -> List[Dict]:
        """Get all CVEs from database with optional pagination"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            query = "SELECT * FROM cves ORDER BY published_date DESC"
            params = []
            
            if limit:
                query += " LIMIT ? OFFSET ?"
                params.extend([limit, offset])
            
            cursor.execute(query, params)
            rows = cursor.fetchall()
            
            columns = [description[0] for description in cursor.description]
            results = []
            
            for row in rows:
                cve_data = dict(zip(columns, row))
                cve_data['tags'] = json.loads(cve_data['tags']) if cve_data['tags'] else []
                cve_data['products'] = json.loads(cve_data['products']) if cve_data['products'] else []
                cve_data['vendors'] = json.loads(cve_data['vendors']) if cve_data['vendors'] else []
                results.append(cve_data)
            
            conn.close()
            return results
            
        except Exception as e:
            self.logger.error(f"Error getting all CVEs: {e}")
            return []
    
    def get_cves_by_severity(self, severity: str) -> List[Dict]:
        """Get all CVEs by specific severity level"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM cves WHERE severity = ? ORDER BY cvss_score DESC', (severity,))
            rows = cursor.fetchall()
            
            columns = [description[0] for description in cursor.description]
            results = []
            
            for row in rows:
                cve_data = dict(zip(columns, row))
                cve_data['tags'] = json.loads(cve_data['tags']) if cve_data['tags'] else []
                cve_data['products'] = json.loads(cve_data['products']) if cve_data['products'] else []
                cve_data['vendors'] = json.loads(cve_data['vendors']) if cve_data['vendors'] else []
                results.append(cve_data)
            
            conn.close()
            return results
            
        except Exception as e:
            self.logger.error(f"Error getting CVEs by severity: {e}")
            return []
    
    def get_cves_by_category(self, category: str) -> List[Dict]:
        """Get all CVEs by specific category"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM cves WHERE category = ? ORDER BY cvss_score DESC', (category,))
            rows = cursor.fetchall()
            
            columns = [description[0] for description in cursor.description]
            results = []
            
            for row in rows:
                cve_data = dict(zip(columns, row))
                cve_data['tags'] = json.loads(cve_data['tags']) if cve_data['tags'] else []
                cve_data['products'] = json.loads(cve_data['products']) if cve_data['products'] else []
                cve_data['vendors'] = json.loads(cve_data['vendors']) if cve_data['vendors'] else []
                results.append(cve_data)
            
            conn.close()
            return results
            
        except Exception as e:
            self.logger.error(f"Error getting CVEs by category: {e}")
            return []
    
    def get_cves_by_vendor(self, vendor: str) -> List[Dict]:
        """Get all CVEs by specific vendor"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM cves WHERE vendors LIKE ? ORDER BY cvss_score DESC', (f'%{vendor}%',))
            rows = cursor.fetchall()
            
            columns = [description[0] for description in cursor.description]
            results = []
            
            for row in rows:
                cve_data = dict(zip(columns, row))
                cve_data['tags'] = json.loads(cve_data['tags']) if cve_data['tags'] else []
                cve_data['products'] = json.loads(cve_data['products']) if cve_data['products'] else []
                cve_data['vendors'] = json.loads(cve_data['vendors']) if cve_data['vendors'] else []
                results.append(cve_data)
            
            conn.close()
            return results
            
        except Exception as e:
            self.logger.error(f"Error getting CVEs by vendor: {e}")
            return []
    
    def get_cves_by_product(self, product: str) -> List[Dict]:
        """Get all CVEs by specific product"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM cves WHERE products LIKE ? ORDER BY cvss_score DESC', (f'%{product}%',))
            rows = cursor.fetchall()
            
            columns = [description[0] for description in cursor.description]
            results = []
            
            for row in rows:
                cve_data = dict(zip(columns, row))
                cve_data['tags'] = json.loads(cve_data['tags']) if cve_data['tags'] else []
                cve_data['products'] = json.loads(cve_data['products']) if cve_data['products'] else []
                cve_data['vendors'] = json.loads(cve_data['vendors']) if cve_data['vendors'] else []
                results.append(cve_data)
            
            conn.close()
            return results
            
        except Exception as e:
            self.logger.error(f"Error getting CVEs by product: {e}")
            return []
    
    def get_critical_cves(self) -> List[Dict]:
        """Get all critical CVEs (CVSS >= 9.0)"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM cves WHERE cvss_score >= 9.0 ORDER BY cvss_score DESC')
            rows = cursor.fetchall()
            
            columns = [description[0] for description in cursor.description]
            results = []
            
            for row in rows:
                cve_data = dict(zip(columns, row))
                cve_data['tags'] = json.loads(cve_data['tags']) if cve_data['tags'] else []
                cve_data['products'] = json.loads(cve_data['products']) if cve_data['products'] else []
                cve_data['vendors'] = json.loads(cve_data['vendors']) if cve_data['vendors'] else []
                results.append(cve_data)
            
            conn.close()
            return results
            
        except Exception as e:
            self.logger.error(f"Error getting critical CVEs: {e}")
            return []
    
    def get_recent_cves(self, days: int = 30) -> List[Dict]:
        """Get CVEs published in the last N days"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cutoff_date = (datetime.now() - timedelta(days=days)).strftime('%Y-%m-%d')
            cursor.execute('SELECT * FROM cves WHERE published_date >= ? ORDER BY published_date DESC', (cutoff_date,))
            rows = cursor.fetchall()
            
            columns = [description[0] for description in cursor.description]
            results = []
            
            for row in rows:
                cve_data = dict(zip(columns, row))
                cve_data['tags'] = json.loads(cve_data['tags']) if cve_data['tags'] else []
                cve_data['products'] = json.loads(cve_data['products']) if cve_data['products'] else []
                cve_data['vendors'] = json.loads(cve_data['vendors']) if cve_data['vendors'] else []
                results.append(cve_data)
            
            conn.close()
            return results
            
        except Exception as e:
            self.logger.error(f"Error getting recent CVEs: {e}")
            return []
    
    def get_cve_summary(self) -> Dict:
        """Get comprehensive CVE summary for easy identification"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get all unique values for easy identification
            cursor.execute('SELECT DISTINCT severity FROM cves ORDER BY severity')
            severities = [row[0] for row in cursor.fetchall()]
            
            cursor.execute('SELECT DISTINCT category FROM cves WHERE category != "" ORDER BY category')
            categories = [row[0] for row in cursor.fetchall()]
            
            cursor.execute('SELECT DISTINCT vendors FROM cves WHERE vendors != ""')
            all_vendors = []
            for row in cursor.fetchall():
                vendors = json.loads(row[0]) if row[0] else []
                all_vendors.extend(vendors)
            unique_vendors = list(set(all_vendors))
            
            cursor.execute('SELECT DISTINCT products FROM cves WHERE products != ""')
            all_products = []
            for row in cursor.fetchall():
                products = json.loads(row[0]) if row[0] else []
                all_products.extend(products)
            unique_products = list(set(all_products))
            
            # Get top CVEs by CVSS score
            cursor.execute('SELECT id, cvss_score, severity, category FROM cves WHERE cvss_score > 0 ORDER BY cvss_score DESC LIMIT 10')
            top_cves = cursor.fetchall()
            
            # Get CVE count by year
            cursor.execute('SELECT substr(published_date, 1, 4) as year, COUNT(*) FROM cves WHERE published_date != "" GROUP BY year ORDER BY year DESC')
            cves_by_year = dict(cursor.fetchall())
            
            conn.close()
            
            return {
                "total_cves": len(self.get_all_cves()),
                "severities": severities,
                "categories": categories,
                "vendors": sorted(unique_vendors),
                "products": sorted(unique_products),
                "top_cves": [{"id": cve[0], "cvss_score": cve[1], "severity": cve[2], "category": cve[3]} for cve in top_cves],
                "cves_by_year": cves_by_year,
                "critical_cves_count": len(self.get_critical_cves()),
                "recent_cves_count": len(self.get_recent_cves(30))
            }
            
        except Exception as e:
            self.logger.error(f"Error getting CVE summary: {e}")
            return {"error": str(e)}
