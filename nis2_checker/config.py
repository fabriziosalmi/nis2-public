import yaml
import os
import sys

def load_config(config_path="config.yaml"):
    """Load configuration from a YAML file."""
    if not os.path.exists(config_path):
        print(f"Error: Configuration file '{config_path}' not found.")
        sys.exit(1)
    
    with open(config_path, 'r') as f:
        try:
            return yaml.safe_load(f)
        except yaml.YAMLError as e:
            print(f"Error parsing configuration file: {e}")
            sys.exit(1)

def load_targets(targets_path="targets.yaml"):
    """Load targets from a YAML file."""
    if not os.path.exists(targets_path):
        print(f"Error: Targets file '{targets_path}' not found.")
        sys.exit(1)
    
    with open(targets_path, 'r') as f:
        try:
            data = yaml.safe_load(f)
            return data.get('targets', [])
        except yaml.YAMLError as e:
            print(f"Error parsing targets file: {e}")
            sys.exit(1)
