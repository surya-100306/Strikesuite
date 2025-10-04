# 🛡️ StrikeSuite Database Usage Guide

## strikesuite.db எப்படி பயன்படுத்துவது?

### 📊 Database Structure (Database அமைப்பு)

```
strikesuite.db
├── scan_history (Scan வரலாறு)
├── vulnerabilities (பாதிப்புகள்)
├── credentials (Credentials)
├── settings (அமைப்புகள்)
├── plugins (Plugins)
├── advanced_scan_results (Advanced Results)
├── threat_intelligence (Threat Intelligence)
└── behavioral_patterns (Behavioral Patterns)
```

### 🔧 Basic Usage (அடிப்படை பயன்பாடு)

#### 1. Database Connection (Database இணைப்பு)
```python
from utils.db_utils import get_db_manager

# Database connection
db_manager = get_db_manager()
db_manager.connect()
```

#### 2. Save Scan Results (Scan Results சேமிப்பது)
```python
# Scan results save பண்ண
scan_result = {
    'scan_type': 'network_scan',
    'target': '192.168.1.1',
    'start_time': '2025-10-04T10:00:00',
    'end_time': '2025-10-04T10:30:00',
    'status': 'completed',
    'results': {
        'open_ports': [22, 80, 443],
        'vulnerabilities': ['SSH Weak Cipher']
    }
}

scan_id = db_manager.save_scan_result(
    scan_result['scan_type'],
    scan_result['target'],
    scan_result['results']
)
```

#### 3. Get Vulnerabilities (Vulnerabilities பெறுவது)
```python
# All vulnerabilities get பண்ண
vulnerabilities = db_manager.get_vulnerabilities()
for vuln in vulnerabilities:
    print(f"Vulnerability: {vuln['vulnerability_type']}")
    print(f"Severity: {vuln['severity']}")
    print(f"Target: {vuln['target']}")
```

#### 4. Get Scan History (Scan History பெறுவது)
```python
# Recent scans get பண்ண
scan_history = db_manager.get_scan_history(limit=10)
for scan in scan_history:
    print(f"Scan: {scan['scan_type']} on {scan['target']}")
    print(f"Status: {scan['status']}")
```

### 🎯 Advanced Usage (மேம்பட்ட பயன்பாடு)

#### 1. Custom Queries (Custom Queries)
```python
import sqlite3

# Direct database access
conn = sqlite3.connect('database/strikesuite.db')
cursor = conn.cursor()

# High severity vulnerabilities
cursor.execute('''
    SELECT target, vulnerability_type, severity 
    FROM vulnerabilities 
    WHERE severity = 'high'
''')
high_vulns = cursor.fetchall()

# Recent scans
cursor.execute('''
    SELECT scan_type, target, created_at 
    FROM scan_history 
    WHERE created_at > datetime('now', '-1 day')
    ORDER BY created_at DESC
''')
recent_scans = cursor.fetchall()

conn.close()
```

#### 2. Settings Management (Settings Management)
```python
# Settings save பண்ண
db_manager.save_setting('max_threads', '100')
db_manager.save_setting('scan_timeout', '30')

# Settings get பண்ண
max_threads = db_manager.get_setting('max_threads', '50')
scan_timeout = db_manager.get_setting('scan_timeout', '30')
```

#### 3. Plugin Management (Plugin Management)
```python
# Plugin information
cursor.execute('SELECT * FROM plugins WHERE enabled = 1')
active_plugins = cursor.fetchall()

for plugin in active_plugins:
    print(f"Plugin: {plugin[1]} v{plugin[2]}")
    print(f"Category: {plugin[5]}")
```

### 📈 Database Analytics (Database Analytics)

#### 1. Vulnerability Statistics
```python
# Severity breakdown
cursor.execute('''
    SELECT severity, COUNT(*) as count 
    FROM vulnerabilities 
    GROUP BY severity 
    ORDER BY count DESC
''')
severity_stats = cursor.fetchall()
```

#### 2. Scan Performance
```python
# Scan duration analysis
cursor.execute('''
    SELECT scan_type, 
           COUNT(*) as total_scans,
           AVG(julianday(end_time) - julianday(start_time)) * 24 * 60 as avg_duration_minutes
    FROM scan_history 
    WHERE status = 'completed'
    GROUP BY scan_type
''')
performance_stats = cursor.fetchall()
```

### 🔍 GUI Integration (GUI Integration)

#### 1. Reporting Tab
```python
# Report generation
def generate_report():
    # Get all scan data
    scan_history = db_manager.get_scan_history()
    vulnerabilities = db_manager.get_vulnerabilities()
    credentials = db_manager.get_credentials()
    
    # Generate report
    report_data = {
        'scans': scan_history,
        'vulnerabilities': vulnerabilities,
        'credentials': credentials
    }
    
    return report_data
```

#### 2. Dashboard Data
```python
# Dashboard statistics
def get_dashboard_stats():
    stats = {}
    
    # Total scans
    cursor.execute('SELECT COUNT(*) FROM scan_history')
    stats['total_scans'] = cursor.fetchone()[0]
    
    # Total vulnerabilities
    cursor.execute('SELECT COUNT(*) FROM vulnerabilities')
    stats['total_vulnerabilities'] = cursor.fetchone()[0]
    
    # High severity count
    cursor.execute('SELECT COUNT(*) FROM vulnerabilities WHERE severity = "high"')
    stats['high_severity'] = cursor.fetchone()[0]
    
    return stats
```

### 🛠️ Database Maintenance (Database Maintenance)

#### 1. Cleanup Old Data
```python
# Clean up old records
deleted_count = db_manager.cleanup_old_data(days=30)
print(f"Cleaned up {deleted_count} old records")
```

#### 2. Database Backup
```python
import shutil
from datetime import datetime

# Backup database
backup_name = f"strikesuite_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
shutil.copy2('database/strikesuite.db', f'backups/{backup_name}')
print(f"Database backed up as {backup_name}")
```

### 📊 Real-time Usage Examples

#### 1. Live Scan Monitoring
```python
def monitor_live_scan(target):
    # Start scan
    scan_id = db_manager.save_scan_result('network_scan', target, {
        'start_time': datetime.now().isoformat(),
        'status': 'running'
    })
    
    # Monitor progress
    while True:
        # Check scan status
        cursor.execute('SELECT status FROM scan_history WHERE id = ?', (scan_id,))
        status = cursor.fetchone()[0]
        
        if status == 'completed':
            break
        
        time.sleep(5)  # Check every 5 seconds
```

#### 2. Vulnerability Tracking
```python
def track_vulnerabilities():
    # Get new vulnerabilities
    cursor.execute('''
        SELECT * FROM vulnerabilities 
        WHERE created_at > datetime('now', '-1 hour')
        ORDER BY created_at DESC
    ''')
    new_vulns = cursor.fetchall()
    
    for vuln in new_vulns:
        print(f"New vulnerability: {vuln[3]} on {vuln[2]}")
        print(f"Severity: {vuln[4]}")
```

### 🎯 Best Practices (Best Practices)

1. **Always use connection management:**
   ```python
   db_manager = get_db_manager()
   if db_manager.connect():
       # Do database operations
       db_manager.disconnect()
   ```

2. **Use transactions for bulk operations:**
   ```python
   db_manager.connection.execute('BEGIN TRANSACTION')
   # Multiple operations
   db_manager.connection.execute('COMMIT')
   ```

3. **Handle errors gracefully:**
   ```python
   try:
       result = db_manager.save_scan_result(...)
   except Exception as e:
       print(f"Database error: {e}")
   ```

4. **Regular cleanup:**
   ```python
   # Clean up old data weekly
   db_manager.cleanup_old_data(days=7)
   ```

### 📚 Summary (சுருக்கம்)

**strikesuite.db** database-ஐ பயன்படுத்துவதற்கான முக்கிய புள்ளிகள்:

- ✅ **Database Structure:** 9 tables with proper relationships
- ✅ **Data Storage:** Scan results, vulnerabilities, credentials
- ✅ **Settings Management:** Application configuration
- ✅ **Plugin System:** Plugin registration and management
- ✅ **Advanced Features:** AI results, threat intelligence, behavioral patterns
- ✅ **Integration:** Easy integration with GUI and CLI
- ✅ **Maintenance:** Built-in cleanup and management functions

**Database ready for production use!** 🚀
