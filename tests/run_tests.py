#!/usr/bin/env python3
"""
Comprehensive Test Runner
Runs all test suites and generates reports
"""

import sys
import subprocess
import json
import logging
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class TestRunner:
    """Orchestrates test execution"""
    
    def __init__(self):
        """Initialize test runner"""
        self.project_root = Path(__file__).parent.parent
        self.results = {}
        self.start_time = datetime.now()
    
    def run_unit_tests(self):
        """Run unit tests"""
        logger.info("=" * 70)
        logger.info("RUNNING UNIT TESTS")
        logger.info("=" * 70)
        
        test_files = [
            "tests/test_utils.py",
            "tests/test_rsa_key_manager.py",
            "tests/test_jwt_middleware.py",
            "tests/test_analysis.py",
            "tests/test_ml_modules.py",
        ]
        
        for test_file in test_files:
            logger.info(f"\nRunning {test_file}...")
            
            result = subprocess.run(
                [sys.executable, "-m", "pytest", test_file, "-v", "--tb=short"],
                cwd=self.project_root,
                capture_output=True,
                text=True
            )
            
            test_name = Path(test_file).stem
            self.results[test_name] = {
                "returncode": result.returncode,
                "passed": result.returncode == 0,
                "output": result.stdout
            }
            
            if result.returncode == 0:
                logger.info(f"✓ {test_file} PASSED")
            else:
                logger.error(f"✗ {test_file} FAILED")
                logger.error(result.stdout)
    
    def run_integration_tests(self):
        """Run integration tests"""
        logger.info("\n" + "=" * 70)
        logger.info("RUNNING INTEGRATION TESTS")
        logger.info("=" * 70)
        
        logger.info("\nRunning tests/test_integration.py...")
        
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/test_integration.py", "-v", "--tb=short"],
            cwd=self.project_root,
            capture_output=True,
            text=True
        )
        
        self.results["test_integration"] = {
            "returncode": result.returncode,
            "passed": result.returncode == 0,
            "output": result.stdout
        }
        
        if result.returncode == 0:
            logger.info("✓ tests/test_integration.py PASSED")
        else:
            logger.error("✗ tests/test_integration.py FAILED")
            logger.error(result.stdout)
    
    def run_all_tests(self):
        """Run all tests"""
        logger.info("\n" + "=" * 70)
        logger.info("RUNNING ALL TESTS")
        logger.info("=" * 70)
        
        result = subprocess.run(
            [sys.executable, "-m", "pytest", "tests/", "-v", "--tb=short", "-ra"],
            cwd=self.project_root,
            capture_output=True,
            text=True
        )
        
        self.results["all_tests"] = {
            "returncode": result.returncode,
            "passed": result.returncode == 0,
            "output": result.stdout
        }
        
        logger.info(result.stdout)
        
        return result.returncode == 0
    
    def generate_report(self):
        """Generate test report"""
        elapsed = (datetime.now() - self.start_time).total_seconds()
        
        passed_count = sum(1 for r in self.results.values() if r.get("passed"))
        total_count = len(self.results)
        
        report = {
            "timestamp": self.start_time.isoformat(),
            "duration_seconds": elapsed,
            "total_suites": total_count,
            "passed_suites": passed_count,
            "failed_suites": total_count - passed_count,
            "success_rate": (passed_count / total_count * 100) if total_count > 0 else 0,
            "results": {name: r["passed"] for name, r in self.results.items()}
        }
        
        logger.info("\n" + "=" * 70)
        logger.info("TEST REPORT")
        logger.info("=" * 70)
        logger.info(f"Total test suites: {total_count}")
        logger.info(f"Passed: {passed_count}")
        logger.info(f"Failed: {total_count - passed_count}")
        logger.info(f"Success rate: {report['success_rate']:.1f}%")
        logger.info(f"Duration: {elapsed:.1f} seconds")
        
        # Detailed results
        for name, r in self.results.items():
            status = "✓ PASS" if r["passed"] else "✗ FAIL"
            logger.info(f"  {status}: {name}")
        
        logger.info("=" * 70 + "\n")
        
        # Save report
        report_path = self.project_root / "data" / "test_report.json"
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Report saved: {report_path}")
        
        return report
    
    def run_coverage(self):
        """Run tests with coverage"""
        logger.info("\n" + "=" * 70)
        logger.info("RUNNING TESTS WITH COVERAGE")
        logger.info("=" * 70)
        
        result = subprocess.run(
            [
                sys.executable, "-m", "pytest", "tests/",
                "--cov=core",
                "--cov=attacks",
                "--cov=analysis",
                "--cov=ml_model",
                "--cov=validation",
                "--cov-report=html",
                "--cov-report=term",
                "-v"
            ],
            cwd=self.project_root,
            capture_output=True,
            text=True
        )
        
        logger.info(result.stdout)
        
        if result.returncode != 0:
            logger.error("Coverage report generation had issues")
        else:
            logger.info("✓ Coverage report generated")
    
    def print_summary(self):
        """Print test summary"""
        print("\n" + "=" * 70)
        print("TEST EXECUTION SUMMARY")
        print("=" * 70)
        
        total_passed = sum(1 for r in self.results.values() if r.get("passed"))
        total_tests = len(self.results)
        
        print(f"\nTest Suites: {total_passed}/{total_tests} passed")
        
        if total_passed == total_tests:
            print("\n✓ ALL TESTS PASSED!")
            return 0
        else:
            print(f"\n✗ {total_tests - total_passed} test suite(s) failed")
            for name, result in self.results.items():
                if not result.get("passed"):
                    print(f"  - {name}")
            return 1


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Run JWT Cryptanalysis tests")
    parser.add_argument("--unit", action="store_true", help="Run unit tests only")
    parser.add_argument("--integration", action="store_true", help="Run integration tests only")
    parser.add_argument("--all", action="store_true", help="Run all tests")
    parser.add_argument("--coverage", action="store_true", help="Run with coverage")
    
    args = parser.parse_args()
    
    runner = TestRunner()
    
    # Default: run all
    if not any([args.unit, args.integration, args.all, args.coverage]):
        args.all = True
    
    try:
        if args.unit:
            runner.run_unit_tests()
        elif args.integration:
            runner.run_integration_tests()
        elif args.all:
            runner.run_all_tests()
        elif args.coverage:
            runner.run_coverage()
        
        if not args.coverage:
            runner.generate_report()
        
        return runner.print_summary()
    
    except Exception as e:
        logger.error(f"Test execution error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
