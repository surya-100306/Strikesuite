#!/usr/bin/env python3
"""
Performance Optimizer
Advanced performance optimization and monitoring capabilities
"""

import time
import psutil
import threading
import queue
import multiprocessing
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from typing import Dict, List, Any, Optional, Callable
import json
import sqlite3
from datetime import datetime, timedelta
import gc
import sys

class PerformanceMonitor:
    """Advanced performance monitoring system"""
    
    def __init__(self):
        self.metrics = {}
        self.start_time = time.time()
        self.monitoring = False
        self.monitor_thread = None
        self.performance_history = []
        
    def start_monitoring(self, interval: float = 1.0):
        """Start performance monitoring"""
        self.monitoring = True
        self.monitor_thread = threading.Thread(target=self._monitor_loop, args=(interval,))
        self.monitor_thread.daemon = True
        self.monitor_thread.start()
        print("Performance monitoring started")
    
    def stop_monitoring(self):
        """Stop performance monitoring"""
        self.monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join()
        print("Performance monitoring stopped")
    
    def _monitor_loop(self, interval: float):
        """Main monitoring loop"""
        while self.monitoring:
            try:
                metrics = self._collect_metrics()
                self.performance_history.append(metrics)
                
                # Keep only last 1000 entries to prevent memory issues
                if len(self.performance_history) > 1000:
                    self.performance_history = self.performance_history[-1000:]
                
                time.sleep(interval)
            except Exception as e:
                print(f"Performance monitoring error: {e}")
                time.sleep(interval)
    
    def _collect_metrics(self) -> Dict[str, Any]:
        """Collect current performance metrics"""
        try:
            # CPU metrics
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_count = psutil.cpu_count()
            cpu_freq = psutil.cpu_freq()
            
            # Memory metrics
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Disk metrics
            disk = psutil.disk_usage('/')
            disk_io = psutil.disk_io_counters()
            
            # Network metrics
            network_io = psutil.net_io_counters()
            
            # Process metrics
            process = psutil.Process()
            process_memory = process.memory_info()
            process_cpu = process.cpu_percent()
            
            # Python-specific metrics
            python_memory = sys.getsizeof(gc.get_objects())
            gc_stats = gc.get_stats()
            
            return {
                "timestamp": datetime.now().isoformat(),
                "cpu": {
                    "percent": cpu_percent,
                    "count": cpu_count,
                    "frequency": cpu_freq.current if cpu_freq else None
                },
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "percent": memory.percent,
                    "used": memory.used,
                    "free": memory.free
                },
                "swap": {
                    "total": swap.total,
                    "used": swap.used,
                    "free": swap.free,
                    "percent": swap.percent
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": (disk.used / disk.total) * 100
                },
                "network": {
                    "bytes_sent": network_io.bytes_sent,
                    "bytes_recv": network_io.bytes_recv,
                    "packets_sent": network_io.packets_sent,
                    "packets_recv": network_io.packets_recv
                },
                "process": {
                    "memory_rss": process_memory.rss,
                    "memory_vms": process_memory.vms,
                    "cpu_percent": process_cpu
                },
                "python": {
                    "memory_usage": python_memory,
                    "gc_stats": gc_stats
                }
            }
        except Exception as e:
            return {"timestamp": datetime.now().isoformat(), "error": str(e)}
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get performance summary"""
        if not self.performance_history:
            return {"message": "No performance data available"}
        
        # Calculate averages
        cpu_avg = sum(m.get("cpu", {}).get("percent", 0) for m in self.performance_history) / len(self.performance_history)
        memory_avg = sum(m.get("memory", {}).get("percent", 0) for m in self.performance_history) / len(self.performance_history)
        
        # Get current metrics
        current_metrics = self.performance_history[-1] if self.performance_history else {}
        
        return {
            "monitoring_duration": time.time() - self.start_time,
            "data_points": len(self.performance_history),
            "averages": {
                "cpu_percent": cpu_avg,
                "memory_percent": memory_avg
            },
            "current": current_metrics,
            "recommendations": self._generate_recommendations()
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate performance recommendations"""
        recommendations = []
        
        if not self.performance_history:
            return recommendations
        
        # Analyze recent performance
        recent_metrics = self.performance_history[-10:] if len(self.performance_history) >= 10 else self.performance_history
        
        # CPU recommendations
        avg_cpu = sum(m.get("cpu", {}).get("percent", 0) for m in recent_metrics) / len(recent_metrics)
        if avg_cpu > 80:
            recommendations.append("High CPU usage detected. Consider optimizing algorithms or reducing concurrent operations.")
        elif avg_cpu > 60:
            recommendations.append("Moderate CPU usage. Monitor for potential bottlenecks.")
        
        # Memory recommendations
        avg_memory = sum(m.get("memory", {}).get("percent", 0) for m in recent_metrics) / len(recent_metrics)
        if avg_memory > 90:
            recommendations.append("Critical memory usage. Consider reducing memory footprint or increasing available memory.")
        elif avg_memory > 80:
            recommendations.append("High memory usage. Monitor for memory leaks.")
        
        return recommendations

class TaskOptimizer:
    """Advanced task optimization system"""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or multiprocessing.cpu_count()
        self.task_queue = queue.Queue()
        self.results = {}
        self.performance_monitor = PerformanceMonitor()
        
    def optimize_scan_tasks(self, scan_tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Optimize scan tasks for better performance"""
        # Group tasks by type for batch processing
        task_groups = self._group_tasks_by_type(scan_tasks)
        
        # Optimize each group
        optimized_tasks = []
        for task_type, tasks in task_groups.items():
            if task_type == "network_scan":
                optimized_tasks.extend(self._optimize_network_scan_tasks(tasks))
            elif task_type == "vulnerability_scan":
                optimized_tasks.extend(self._optimize_vulnerability_scan_tasks(tasks))
            elif task_type == "api_test":
                optimized_tasks.extend(self._optimize_api_test_tasks(tasks))
            else:
                optimized_tasks.extend(tasks)
        
        return optimized_tasks
    
    def _group_tasks_by_type(self, tasks: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        """Group tasks by type for optimization"""
        groups = {}
        for task in tasks:
            task_type = task.get("type", "unknown")
            if task_type not in groups:
                groups[task_type] = []
            groups[task_type].append(task)
        return groups
    
    def _optimize_network_scan_tasks(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Optimize network scan tasks"""
        # Group by IP ranges for efficient scanning
        ip_groups = {}
        for task in tasks:
            target = task.get("target", "")
            if target not in ip_groups:
                ip_groups[target] = []
            ip_groups[target].append(task)
        
        optimized_tasks = []
        for target, target_tasks in ip_groups.items():
            # Combine port lists for same target
            all_ports = set()
            for task in target_tasks:
                all_ports.update(task.get("ports", []))
            
            # Create optimized task
            optimized_task = {
                "type": "network_scan",
                "target": target,
                "ports": list(all_ports),
                "optimized": True,
                "original_tasks": len(target_tasks)
            }
            optimized_tasks.append(optimized_task)
        
        return optimized_tasks
    
    def _optimize_vulnerability_scan_tasks(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Optimize vulnerability scan tasks"""
        # Group by host for efficient scanning
        host_groups = {}
        for task in tasks:
            host = task.get("host", "")
            if host not in host_groups:
                host_groups[host] = []
            host_groups[host].append(task)
        
        optimized_tasks = []
        for host, host_tasks in host_groups.items():
            # Combine scan types for same host
            all_scan_types = set()
            for task in host_tasks:
                all_scan_types.add(task.get("scan_type", "basic"))
            
            # Create optimized task
            optimized_task = {
                "type": "vulnerability_scan",
                "host": host,
                "scan_types": list(all_scan_types),
                "optimized": True,
                "original_tasks": len(host_tasks)
            }
            optimized_tasks.append(optimized_task)
        
        return optimized_tasks
    
    def _optimize_api_test_tasks(self, tasks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Optimize API test tasks"""
        # Group by base URL for efficient testing
        url_groups = {}
        for task in tasks:
            base_url = task.get("base_url", "")
            if base_url not in url_groups:
                url_groups[base_url] = []
            url_groups[base_url].append(task)
        
        optimized_tasks = []
        for base_url, url_tasks in url_groups.items():
            # Combine endpoints for same base URL
            all_endpoints = []
            for task in url_tasks:
                all_endpoints.extend(task.get("endpoints", []))
            
            # Create optimized task
            optimized_task = {
                "type": "api_test",
                "base_url": base_url,
                "endpoints": all_endpoints,
                "optimized": True,
                "original_tasks": len(url_tasks)
            }
            optimized_tasks.append(optimized_task)
        
        return optimized_tasks

class MemoryOptimizer:
    """Memory optimization utilities"""
    
    @staticmethod
    def optimize_memory_usage():
        """Optimize memory usage"""
        # Force garbage collection
        collected = gc.collect()
        print(f"Garbage collection freed {collected} objects")
        
        # Get memory usage
        memory_info = psutil.Process().memory_info()
        print(f"Current memory usage: {memory_info.rss / 1024 / 1024:.2f} MB")
        
        return {
            "objects_collected": collected,
            "memory_usage_mb": memory_info.rss / 1024 / 1024,
            "memory_usage_percent": psutil.virtual_memory().percent
        }
    
    @staticmethod
    def clear_caches():
        """Clear various caches to free memory"""
        # Clear Python cache
        sys.modules.clear()
        
        # Clear any application-specific caches
        # This would be customized based on the application
        
        print("Caches cleared")
    
    @staticmethod
    def get_memory_usage() -> Dict[str, Any]:
        """Get detailed memory usage information"""
        process = psutil.Process()
        memory_info = process.memory_info()
        memory_percent = process.memory_percent()
        
        system_memory = psutil.virtual_memory()
        
        return {
            "process_memory": {
                "rss": memory_info.rss,
                "vms": memory_info.vms,
                "percent": memory_percent
            },
            "system_memory": {
                "total": system_memory.total,
                "available": system_memory.available,
                "used": system_memory.used,
                "free": system_memory.free,
                "percent": system_memory.percent
            },
            "python_objects": {
                "total_objects": len(gc.get_objects()),
                "gc_stats": gc.get_stats()
            }
        }

class DatabaseOptimizer:
    """Database optimization utilities"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
    
    def optimize_database(self) -> Dict[str, Any]:
        """Optimize database performance"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get database info
            cursor.execute("PRAGMA database_list")
            databases = cursor.fetchall()
            
            # Analyze tables
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            # Optimize each table
            optimization_results = []
            for table in tables:
                table_name = table[0]
                result = self._optimize_table(cursor, table_name)
                optimization_results.append(result)
            
            # Run VACUUM to reclaim space
            cursor.execute("VACUUM")
            
            # Update statistics
            cursor.execute("ANALYZE")
            
            conn.close()
            
            return {
                "success": True,
                "tables_optimized": len(tables),
                "optimization_results": optimization_results
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def _optimize_table(self, cursor, table_name: str) -> Dict[str, Any]:
        """Optimize a specific table"""
        try:
            # Get table info
            cursor.execute(f"PRAGMA table_info({table_name})")
            columns = cursor.fetchall()
            
            # Get row count
            cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
            row_count = cursor.fetchone()[0]
            
            # Check for indexes
            cursor.execute(f"PRAGMA index_list({table_name})")
            indexes = cursor.fetchall()
            
            return {
                "table_name": table_name,
                "columns": len(columns),
                "row_count": row_count,
                "indexes": len(indexes),
                "optimized": True
            }
            
        except Exception as e:
            return {
                "table_name": table_name,
                "error": str(e),
                "optimized": False
            }
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get database size
            cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
            db_size = cursor.fetchone()[0]
            
            # Get table statistics
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = cursor.fetchall()
            
            table_stats = []
            for table in tables:
                table_name = table[0]
                cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
                row_count = cursor.fetchone()[0]
                table_stats.append({
                    "name": table_name,
                    "rows": row_count
                })
            
            conn.close()
            
            return {
                "database_size_bytes": db_size,
                "database_size_mb": db_size / 1024 / 1024,
                "tables": len(tables),
                "table_stats": table_stats
            }
            
        except Exception as e:
            return {"error": str(e)}

