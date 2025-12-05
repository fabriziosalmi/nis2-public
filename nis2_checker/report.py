import json
import sys
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

def print_console_report(results):
    """Print a human-readable report to the console."""
    print("\n" + "="*60)
    print(f"{Fore.CYAN}NIS2 Compliance Check Report{Style.RESET_ALL}")
    print("="*60 + "\n")

    total_targets = len(results)
    passed_targets = 0

    for result in results:
        name = result['name']
        target = result['target']
        print(f"Target: {Fore.BLUE}{name}{Style.RESET_ALL} ({target})")
        
        all_passed = True
        for check_name, check_result in result['checks'].items():
            status = check_result['status']
            details = check_result['details']
            
            if status == "PASS":
                color = Fore.GREEN
                symbol = "✓"
            elif status == "FAIL":
                color = Fore.RED
                symbol = "✗"
                all_passed = False
            else:
                color = Fore.YELLOW
                symbol = "-"
                
            print(f"  [{color}{symbol}{Style.RESET_ALL}] {check_name}: {details}")
        
        if all_passed:
            passed_targets += 1
        print("-" * 40)

    print(f"\nSummary: {passed_targets}/{total_targets} targets passed all checks.")

def save_json_report(results, filename="report.json"):
    """Save results to a JSON file."""
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nReport saved to {filename}")
    except Exception as e:
        print(f"Error saving report: {e}")
