#!/usr/bin/env python3
"""
Single Credential Test Thread
Thread for testing individual credentials
"""

from PyQt5.QtCore import QThread, pyqtSignal

class SingleCredentialTestThread(QThread):
    """Thread for testing a single credential"""
    result = pyqtSignal(dict)
    
    def __init__(self, target, username, password, options):
        super().__init__()
        self.target = target
        self.username = username
        self.password = password
        self.options = options
        
    def run(self):
        """Test a single credential"""
        try:
            try:
                from core.brute_forcer import BruteForcer
            except ImportError:
                self.result.emit({'error': 'BruteForcer module not available', 'success': False})
                return
            
            brute_forcer = BruteForcer()
            
            # Test the credential against the specified service
            service = self.options.get('service', 'ssh').lower()
            port = self.options.get('port', 22)
            
            # Test the credential
            if service == 'ssh':
                result = brute_forcer._test_ssh_credentials(self.target, port, self.username, self.password)
            elif service == 'ftp':
                result = brute_forcer._test_ftp_credentials(self.target, port, self.username, self.password)
            elif service == 'http':
                result = brute_forcer._test_http_credentials(self.target, port, self.username, self.password, '/admin')
            elif service == 'mysql':
                result = brute_forcer._test_mysql_credentials(self.target, port, self.username, self.password)
            elif service == 'postgresql':
                result = brute_forcer._test_postgresql_credentials(self.target, port, self.username, self.password)
            else:
                result = None
            
            if result:
                result['service'] = service.upper()
                result['success'] = True
                self.result.emit(result)
            else:
                self.result.emit({
                    'username': self.username,
                    'password': self.password,
                    'service': service.upper(),
                    'success': False,
                    'error': 'Authentication failed'
                })
                
        except Exception as e:
            self.result.emit({
                'username': self.username,
                'password': self.password,
                'success': False,
                'error': str(e)
            })
