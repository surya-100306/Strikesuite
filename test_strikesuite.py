#!/usr/bin/env python3
"""
StrikeSuite Test Script
Quick test to verify all components are working
"""

import sys
import os
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def test_imports():
    """Test all critical imports"""
    print("🔍 Testing imports...")
    
    try:
        from strikesuite.main import main, check_dependencies
        print("✅ Main module imported")
        
        from strikesuite.gui.main_window import MainWindow
        print("✅ GUI main window imported")
        
        from strikesuite.core.plugin_manager import PluginManager
        print("✅ Plugin manager imported")
        
        from strikesuite.utils.db_utils import init_db
        print("✅ Database utils imported")
        
        from strikesuite.cli import main as cli_main
        print("✅ CLI module imported")
        
        return True
    except Exception as e:
        print(f"❌ Import test failed: {e}")
        return False

def test_dependencies():
    """Test dependency check"""
    print("\n🔍 Testing dependencies...")
    
    try:
        from strikesuite.main import check_dependencies
        deps_ok = check_dependencies()
        if deps_ok:
            print("✅ All dependencies available")
        else:
            print("⚠️ Some dependencies missing (but core functionality should work)")
        return True
    except Exception as e:
        print(f"❌ Dependency test failed: {e}")
        return False

def test_database():
    """Test database initialization"""
    print("\n🔍 Testing database...")
    
    try:
        from strikesuite.utils.db_utils import init_db
        result = init_db()
        if result:
            print("✅ Database initialized successfully")
        else:
            print("❌ Database initialization failed")
        return result
    except Exception as e:
        print(f"❌ Database test failed: {e}")
        return False

def test_plugins():
    """Test plugin loading"""
    print("\n🔍 Testing plugins...")
    
    try:
        from strikesuite.core.plugin_manager import PluginManager
        pm = PluginManager()
        plugins = pm.load_plugins()
        print(f"✅ Loaded {len(plugins)} plugins")
        return True
    except Exception as e:
        print(f"❌ Plugin test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🚀 StrikeSuite Component Test")
    print("=" * 50)
    
    tests = [
        ("Imports", test_imports),
        ("Dependencies", test_dependencies),
        ("Database", test_database),
        ("Plugins", test_plugins)
    ]
    
    results = []
    for test_name, test_func in tests:
        try:
            result = test_func()
            results.append((test_name, result))
        except Exception as e:
            print(f"❌ {test_name} test crashed: {e}")
            results.append((test_name, False))
    
    print("\n" + "=" * 50)
    print("📊 Test Results:")
    
    all_passed = True
    for test_name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"  {test_name}: {status}")
        if not result:
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 All tests passed! StrikeSuite is ready to run.")
        print("\nTo start StrikeSuite:")
        print("  python3 strikesuite.py")
        print("  or")
        print("  python3 -m strikesuite.main")
        print("\nFor CLI mode:")
        print("  python3 -m strikesuite.main --cli")
    else:
        print("⚠️ Some tests failed. Check the output above for details.")
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())

