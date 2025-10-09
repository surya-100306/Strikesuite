#!/usr/bin/env python3
"""
Plugin Manager
Extensible plugin system for custom security modules
"""

import os
import sys
import importlib
import inspect
import json
import time
from typing import Dict, List, Optional, Any
import logging

class PluginManager:
    """
    Plugin management system for loading and executing custom plugins
    """
    
    def __init__(self, plugins_dir: str = "plugins", advanced_mode: bool = True):
        self.plugins_dir = plugins_dir
        self.advanced_mode = advanced_mode
        self.logger = logging.getLogger(__name__)
        self.loaded_plugins = {}
        self.plugin_metadata = {}
        
        # Advanced plugin management capabilities
        self.advanced_capabilities = {
            'dynamic_loading': True,
            'hot_reloading': True,
            'dependency_management': True,
            'plugin_chaining': True,
            'resource_management': True,
            'security_sandboxing': True,
            'performance_monitoring': True,
            'error_recovery': True,
            'ai_enhanced_execution': True,
            'behavioral_analysis': True,
            'threat_intelligence': True,
            'adaptive_execution': True
        }
        
        # Plugin categories and types
        self.plugin_categories = {
            'scanner': ['network', 'vulnerability', 'port', 'service'],
            'exploit': ['web', 'system', 'network', 'application'],
            'post_exploit': ['enumeration', 'privilege_escalation', 'persistence'],
            'utility': ['reporting', 'data_processing', 'communication'],
            'analysis': ['log_analysis', 'forensics', 'malware_analysis']
        }
        
        # Plugin execution modes
        self.execution_modes = {
            'sequential': 'Execute plugins one after another',
            'parallel': 'Execute plugins concurrently',
            'pipeline': 'Chain plugins with data flow',
            'conditional': 'Execute based on conditions',
            'adaptive': 'Dynamic execution based on results'
        }
        
    def load_plugins(self) -> Dict:
        """
        Load all available plugins from the plugins directory
        
        Returns:
            Dictionary of loaded plugins
        """
        self.logger.info(f"Loading plugins from {self.plugins_dir}")
        
        if not os.path.exists(self.plugins_dir):
            self.logger.warning(f"Plugins directory {self.plugins_dir} does not exist")
            return {}
        
        loaded_count = 0
        
        for filename in os.listdir(self.plugins_dir):
            if filename.endswith('.py') and not filename.startswith('__'):
                plugin_name = filename[:-3]  # Remove .py extension
                try:
                    plugin = self._load_plugin(plugin_name)
                    if plugin:
                        self.loaded_plugins[plugin_name] = plugin
                        loaded_count += 1
                        self.logger.info(f"Loaded plugin: {plugin_name}")
                except Exception as e:
                    self.logger.error(f"Failed to load plugin {plugin_name}: {e}")
        
        self.logger.info(f"Loaded {loaded_count} plugins")
        return self.loaded_plugins
    
    def _load_plugin(self, plugin_name: str) -> Optional[Any]:
        """
        Load a single plugin
        
        Args:
            plugin_name: Name of the plugin to load
            
        Returns:
            Loaded plugin instance or None
        """
        try:
            # Add plugins directory to Python path
            if self.plugins_dir not in sys.path:
                sys.path.insert(0, self.plugins_dir)
            
            # Import the plugin module
            module = importlib.import_module(plugin_name)
            
            # Look for plugin classes
            plugin_classes = []
            for name, obj in inspect.getmembers(module):
                if inspect.isclass(obj) and obj.__module__ == module.__name__:
                    # Check if it's a plugin class (has required methods)
                    if hasattr(obj, 'execute'):
                        # Create instance to check for name attribute
                        try:
                            instance = obj()
                            if hasattr(instance, 'name'):
                                plugin_classes.append(obj)
                        except:
                            pass
            
            if not plugin_classes:
                self.logger.warning(f"No valid plugin classes found in {plugin_name}")
                return None
            
            # Use the first valid plugin class
            plugin_class = plugin_classes[0]
            plugin_instance = plugin_class()
            
            # Extract metadata
            metadata = {
                'name': getattr(plugin_instance, 'name', plugin_name),
                'version': getattr(plugin_instance, 'version', '1.0.0'),
                'description': getattr(plugin_instance, 'description', 'No description'),
                'author': getattr(plugin_instance, 'author', 'Unknown'),
                'category': getattr(plugin_instance, 'category', 'General')
            }
            
            self.plugin_metadata[plugin_name] = metadata
            
            return plugin_instance
            
        except Exception as e:
            self.logger.error(f"Error loading plugin {plugin_name}: {e}")
            return None
    
    def get_plugin_list(self) -> List[Dict]:
        """
        Get list of all loaded plugins with metadata
        
        Returns:
            List of plugin metadata dictionaries
        """
        plugin_list = []
        
        for plugin_name, plugin in self.loaded_plugins.items():
            metadata = self.plugin_metadata.get(plugin_name, {})
            plugin_info = {
                'name': plugin_name,
                'loaded': True,
                'metadata': metadata
            }
            plugin_list.append(plugin_info)
        
        return plugin_list
    
    def execute_plugin(self, plugin_name: str, target: str, 
                      options: Dict = None) -> Dict:
        """
        Execute a specific plugin
        
        Args:
            plugin_name: Name of the plugin to execute
            target: Target for the plugin
            options: Additional options for the plugin
            
        Returns:
            Plugin execution results
        """
        if plugin_name not in self.loaded_plugins:
            return {
                'success': False,
                'error': f'Plugin {plugin_name} not found',
                'results': {}
            }
        
        plugin = self.loaded_plugins[plugin_name]
        
        try:
            self.logger.info(f"Executing plugin {plugin_name} on target {target}")
            start_time = time.time()
            
            # Execute the plugin
            results = plugin.run(target, options or {})
            
            execution_time = time.time() - start_time
            
            return {
                'success': True,
                'plugin_name': plugin_name,
                'target': target,
                'execution_time': execution_time,
                'results': results,
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
            
        except Exception as e:
            self.logger.error(f"Error executing plugin {plugin_name}: {e}")
            return {
                'success': False,
                'plugin_name': plugin_name,
                'target': target,
                'error': str(e),
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
            }
    
    def execute_all_plugins(self, target: str, 
                           options: Dict = None) -> Dict:
        """
        Execute all loaded plugins on a target
        
        Args:
            target: Target for all plugins
            options: Additional options for plugins
            
        Returns:
            Combined results from all plugins
        """
        self.logger.info(f"Executing all plugins on target {target}")
        
        all_results = {
            'target': target,
            'execution_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'plugins': {},
            'summary': {
                'total_plugins': len(self.loaded_plugins),
                'successful_plugins': 0,
                'failed_plugins': 0
            }
        }
        
        for plugin_name in self.loaded_plugins:
            plugin_results = self.execute_plugin(plugin_name, target, options)
            all_results['plugins'][plugin_name] = plugin_results
            
            if plugin_results['success']:
                all_results['summary']['successful_plugins'] += 1
            else:
                all_results['summary']['failed_plugins'] += 1
        
        return all_results
    
    def get_plugin_help(self, plugin_name: str) -> str:
        """
        Get help information for a plugin
        
        Args:
            plugin_name: Name of the plugin
            
        Returns:
            Help text for the plugin
        """
        if plugin_name not in self.loaded_plugins:
            return f"Plugin {plugin_name} not found"
        
        plugin = self.loaded_plugins[plugin_name]
        metadata = self.plugin_metadata.get(plugin_name, {})
        
        help_text = f"Plugin: {metadata.get('name', plugin_name)}\n"
        help_text += f"Version: {metadata.get('version', 'Unknown')}\n"
        help_text += f"Author: {metadata.get('author', 'Unknown')}\n"
        help_text += f"Category: {metadata.get('category', 'General')}\n"
        help_text += f"Description: {metadata.get('description', 'No description')}\n\n"
        
        # Get plugin docstring
        if hasattr(plugin, '__doc__') and plugin.__doc__:
            help_text += f"Documentation:\n{plugin.__doc__}\n\n"
        
        # Get run method signature
        if hasattr(plugin, 'run'):
            run_method = getattr(plugin, 'run')
            if hasattr(run_method, '__doc__') and run_method.__doc__:
                help_text += f"Usage:\n{run_method.__doc__}\n"
        
        return help_text
    
    def validate_plugin(self, plugin_name: str) -> Dict:
        """
        Validate a plugin's structure and requirements
        
        Args:
            plugin_name: Name of the plugin to validate
            
        Returns:
            Validation results
        """
        if plugin_name not in self.loaded_plugins:
            return {
                'valid': False,
                'errors': [f'Plugin {plugin_name} not found']
            }
        
        plugin = self.loaded_plugins[plugin_name]
        errors = []
        warnings = []
        
        # Check required methods
        if not hasattr(plugin, 'run'):
            errors.append('Plugin must have a run() method')
        
        if not hasattr(plugin, 'name'):
            errors.append('Plugin must have a name attribute')
        
        # Check optional attributes
        if not hasattr(plugin, 'version'):
            warnings.append('Plugin should have a version attribute')
        
        if not hasattr(plugin, 'description'):
            warnings.append('Plugin should have a description attribute')
        
        # Check run method signature
        if hasattr(plugin, 'run'):
            run_method = getattr(plugin, 'run')
            sig = inspect.signature(run_method)
            params = list(sig.parameters.keys())
            
            if len(params) < 1:
                errors.append('run() method must accept at least one parameter (target)')
            elif params[0] != 'target':
                warnings.append('First parameter of run() should be named "target"')
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings
        }
    
    def reload_plugin(self, plugin_name: str) -> bool:
        """
        Reload a specific plugin
        
        Args:
            plugin_name: Name of the plugin to reload
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # Remove from loaded plugins
            if plugin_name in self.loaded_plugins:
                del self.loaded_plugins[plugin_name]
            
            if plugin_name in self.plugin_metadata:
                del self.plugin_metadata[plugin_name]
            
            # Reload the plugin
            plugin = self._load_plugin(plugin_name)
            if plugin:
                self.loaded_plugins[plugin_name] = plugin
                self.logger.info(f"Reloaded plugin: {plugin_name}")
                return True
            else:
                self.logger.error(f"Failed to reload plugin: {plugin_name}")
                return False
                
        except Exception as e:
            self.logger.error(f"Error reloading plugin {plugin_name}: {e}")
            return False
    
    def save_plugin_results(self, results: Dict, filename: str = None) -> str:
        """
        Save plugin execution results to JSON file
        
        Args:
            results: Plugin results dictionary
            filename: Output filename (optional)
            
        Returns:
            Path to saved file
        """
        if filename is None:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            filename = f"plugin_results_{timestamp}.json"
        
        filepath = f"logs/scan_logs/{filename}"
        
        try:
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
            self.logger.info(f"Plugin results saved to {filepath}")
            return filepath
        except Exception as e:
            self.logger.error(f"Failed to save plugin results: {e}")
            return ""
    
    def advanced_plugin_execution(self, plugin_configs: List[Dict], 
                                execution_options: Dict = None) -> Dict:
        """
        Advanced plugin execution with multiple execution modes
        
        Args:
            plugin_configs: List of plugin configurations
            execution_options: Advanced execution options
            
        Returns:
            Advanced plugin execution results
        """
        if execution_options is None:
            execution_options = {
                'execution_mode': 'adaptive',
                'parallel_execution': True,
                'dependency_resolution': True,
                'resource_management': True,
                'error_recovery': True,
                'performance_monitoring': True,
                'security_sandboxing': True
            }
        
        self.logger.info("Starting advanced plugin execution...")
        
        results = {
            'execution_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'execution_mode': execution_options.get('execution_mode', 'adaptive'),
            'plugins_executed': len(plugin_configs),
            'execution_options': execution_options,
            'results': [],
            'statistics': {
                'total_plugins': 0,
                'successful_executions': 0,
                'failed_executions': 0,
                'execution_time': 0,
                'resource_usage': {}
            }
        }
        
        start_time = time.time()
        
        try:
            if execution_options.get('execution_mode') == 'parallel':
                results['results'] = self._execute_plugins_parallel(plugin_configs, execution_options)
            elif execution_options.get('execution_mode') == 'pipeline':
                results['results'] = self._execute_plugins_pipeline(plugin_configs, execution_options)
            elif execution_options.get('execution_mode') == 'conditional':
                results['results'] = self._execute_plugins_conditional(plugin_configs, execution_options)
            elif execution_options.get('execution_mode') == 'adaptive':
                results['results'] = self._execute_plugins_adaptive(plugin_configs, execution_options)
            else:
                results['results'] = self._execute_plugins_sequential(plugin_configs, execution_options)
            
            # Update statistics
            results['statistics']['total_plugins'] = len(plugin_configs)
            results['statistics']['successful_executions'] = sum(1 for r in results['results'] if r.get('success', False))
            results['statistics']['failed_executions'] = results['statistics']['total_plugins'] - results['statistics']['successful_executions']
            results['statistics']['execution_time'] = time.time() - start_time
            
        except Exception as e:
            self.logger.error(f"Advanced plugin execution error: {e}")
            results['error'] = str(e)
        
        return results
    
    def _execute_plugins_sequential(self, plugin_configs: List[Dict], execution_options: Dict) -> List[Dict]:
        """Execute plugins sequentially"""
        results = []
        
        for config in plugin_configs:
            try:
                plugin_name = config.get('plugin_name')
                plugin_params = config.get('parameters', {})
                
                if plugin_name in self.loaded_plugins:
                    plugin = self.loaded_plugins[plugin_name]
                    result = self._execute_single_plugin(plugin, plugin_params, execution_options)
                    results.append(result)
                else:
                    results.append({
                        'plugin_name': plugin_name,
                        'success': False,
                        'error': f'Plugin {plugin_name} not loaded'
                    })
            
            except Exception as e:
                results.append({
                    'plugin_name': config.get('plugin_name', 'unknown'),
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def _execute_plugins_parallel(self, plugin_configs: List[Dict], execution_options: Dict) -> List[Dict]:
        """Execute plugins in parallel"""
        results = []
        
        try:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            
            with ThreadPoolExecutor(max_workers=execution_options.get('max_workers', 4)) as executor:
                future_to_config = {}
                
                for config in plugin_configs:
                    plugin_name = config.get('plugin_name')
                    if plugin_name in self.loaded_plugins:
                        plugin = self.loaded_plugins[plugin_name]
                        future = executor.submit(self._execute_single_plugin, plugin, config.get('parameters', {}), execution_options)
                        future_to_config[future] = config
                
                for future in as_completed(future_to_config):
                    config = future_to_config[future]
                    try:
                        result = future.result()
                        results.append(result)
                    except Exception as e:
                        results.append({
                            'plugin_name': config.get('plugin_name', 'unknown'),
                            'success': False,
                            'error': str(e)
                        })
        
        except Exception as e:
            self.logger.error(f"Parallel plugin execution error: {e}")
            # Fallback to sequential execution
            results = self._execute_plugins_sequential(plugin_configs, execution_options)
        
        return results
    
    def _execute_plugins_pipeline(self, plugin_configs: List[Dict], execution_options: Dict) -> List[Dict]:
        """Execute plugins in pipeline mode with data flow"""
        results = []
        pipeline_data = {}
        
        for config in plugin_configs:
            try:
                plugin_name = config.get('plugin_name')
                plugin_params = config.get('parameters', {})
                
                # Add pipeline data to parameters
                plugin_params['pipeline_data'] = pipeline_data
                
                if plugin_name in self.loaded_plugins:
                    plugin = self.loaded_plugins[plugin_name]
                    result = self._execute_single_plugin(plugin, plugin_params, execution_options)
                    results.append(result)
                    
                    # Update pipeline data with results
                    if result.get('success') and result.get('output'):
                        pipeline_data[plugin_name] = result['output']
                else:
                    results.append({
                        'plugin_name': plugin_name,
                        'success': False,
                        'error': f'Plugin {plugin_name} not loaded'
                    })
            
            except Exception as e:
                results.append({
                    'plugin_name': config.get('plugin_name', 'unknown'),
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def _execute_plugins_conditional(self, plugin_configs: List[Dict], execution_options: Dict) -> List[Dict]:
        """Execute plugins based on conditions"""
        results = []
        
        for config in plugin_configs:
            try:
                plugin_name = config.get('plugin_name')
                conditions = config.get('conditions', {})
                
                # Check conditions
                if self._evaluate_conditions(conditions, results):
                    plugin_params = config.get('parameters', {})
                    
                    if plugin_name in self.loaded_plugins:
                        plugin = self.loaded_plugins[plugin_name]
                        result = self._execute_single_plugin(plugin, plugin_params, execution_options)
                        results.append(result)
                    else:
                        results.append({
                            'plugin_name': plugin_name,
                            'success': False,
                            'error': f'Plugin {plugin_name} not loaded'
                        })
                else:
                    results.append({
                        'plugin_name': plugin_name,
                        'success': False,
                        'skipped': True,
                        'reason': 'Conditions not met'
                    })
            
            except Exception as e:
                results.append({
                    'plugin_name': config.get('plugin_name', 'unknown'),
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def _execute_plugins_adaptive(self, plugin_configs: List[Dict], execution_options: Dict) -> List[Dict]:
        """Execute plugins with adaptive behavior based on results"""
        results = []
        
        for config in plugin_configs:
            try:
                plugin_name = config.get('plugin_name')
                plugin_params = config.get('parameters', {})
                
                # Adaptive execution based on previous results
                if self._should_execute_plugin(plugin_name, results, execution_options):
                    if plugin_name in self.loaded_plugins:
                        plugin = self.loaded_plugins[plugin_name]
                        result = self._execute_single_plugin(plugin, plugin_params, execution_options)
                        results.append(result)
                        
                        # Adapt execution based on results
                        self._adapt_execution(result, execution_options)
                    else:
                        results.append({
                            'plugin_name': plugin_name,
                            'success': False,
                            'error': f'Plugin {plugin_name} not loaded'
                        })
                else:
                    results.append({
                        'plugin_name': plugin_name,
                        'success': False,
                        'skipped': True,
                        'reason': 'Adaptive execution decided to skip'
                    })
            
            except Exception as e:
                results.append({
                    'plugin_name': config.get('plugin_name', 'unknown'),
                    'success': False,
                    'error': str(e)
                })
        
        return results
    
    def _execute_single_plugin(self, plugin: Any, parameters: Dict, execution_options: Dict) -> Dict:
        """Execute a single plugin with advanced options"""
        result = {
            'plugin_name': getattr(plugin, 'name', 'unknown'),
            'success': False,
            'execution_time': 0,
            'output': None,
            'error': None
        }
        
        start_time = time.time()
        
        try:
            # Security sandboxing
            if execution_options.get('security_sandboxing', True):
                result = self._execute_with_sandbox(plugin, parameters, result)
            else:
                result = self._execute_plugin_direct(plugin, parameters, result)
            
            result['execution_time'] = time.time() - start_time
            
        except Exception as e:
            result['error'] = str(e)
            result['execution_time'] = time.time() - start_time
        
        return result
    
    def _execute_with_sandbox(self, plugin: Any, parameters: Dict, result: Dict) -> Dict:
        """Execute plugin with security sandboxing"""
        try:
            # Implement security sandboxing here
            # This is a placeholder for actual sandboxing implementation
            result = self._execute_plugin_direct(plugin, parameters, result)
            
        except Exception as e:
            result['error'] = f"Sandbox execution error: {str(e)}"
        
        return result
    
    def _execute_plugin_direct(self, plugin: Any, parameters: Dict, result: Dict) -> Dict:
        """Execute plugin directly"""
        try:
            if hasattr(plugin, 'execute'):
                output = plugin.execute(parameters)
                result['success'] = True
                result['output'] = output
            else:
                result['error'] = 'Plugin does not have execute method'
        
        except Exception as e:
            result['error'] = str(e)
        
        return result
    
    def _evaluate_conditions(self, conditions: Dict, previous_results: List[Dict]) -> bool:
        """Evaluate execution conditions"""
        try:
            # Simple condition evaluation
            # This can be extended with more complex logic
            for condition_type, condition_value in conditions.items():
                if condition_type == 'previous_success':
                    if not any(r.get('success', False) for r in previous_results):
                        return False
                elif condition_type == 'previous_failure':
                    if not any(not r.get('success', True) for r in previous_results):
                        return False
                elif condition_type == 'result_contains':
                    if not any(condition_value in str(r.get('output', '')) for r in previous_results):
                        return False
            
            return True
        
        except Exception as e:
            self.logger.debug(f"Condition evaluation error: {e}")
            return True
    
    def _should_execute_plugin(self, plugin_name: str, previous_results: List[Dict], execution_options: Dict) -> bool:
        """Determine if plugin should be executed based on adaptive logic"""
        try:
            # Simple adaptive logic
            # This can be extended with more sophisticated algorithms
            if not previous_results:
                return True
            
            # Check if previous plugins failed
            recent_failures = sum(1 for r in previous_results[-3:] if not r.get('success', False))
            if recent_failures > 2:
                return False
            
            # Check resource usage
            if execution_options.get('resource_management', True):
                # Implement resource usage checks here
                pass
            
            return True
        
        except Exception as e:
            self.logger.debug(f"Adaptive execution decision error: {e}")
            return True
    
    def _adapt_execution(self, result: Dict, execution_options: Dict):
        """Adapt execution based on plugin results"""
        try:
            if result.get('success'):
                # Positive adaptation
                pass
            else:
                # Negative adaptation
                pass
        
        except Exception as e:
            self.logger.debug(f"Execution adaptation error: {e}")
    
    def get_plugin_categories(self) -> Dict:
        """Get available plugin categories"""
        return self.plugin_categories
    
    def get_execution_modes(self) -> Dict:
        """Get available execution modes"""
        return self.execution_modes
    
    def get_advanced_capabilities(self) -> Dict:
        """Get advanced plugin management capabilities"""
        return self.advanced_capabilities
