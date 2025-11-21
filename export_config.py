#!/usr/bin/env python3

#
#  Export candidate configuration from Panorama
#

from pathlib import Path
import sys
from datetime import datetime
import argparse
from panorama_client import get_client

#=====================================================
   #  Export configuration from Panorama

   # Args:
    #    force: Force export even if no changes detected
    
  #  Returns:
       # 0 on success, 1 on failure
#=========================================================

def export_config(force: bool=False):

    try:

        client = get_client()
        if not force:
            status = client.get_commit_status()
            if not status['has_pending_changes']:
                print("ℹ️ No pending changes in Panorama candidate config")
                return 0
        else:
            print("Force mode: skipping change check")

        print("Exporting configuration...")

        config_xml = client.get_candidate_config()
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')

        config_folder = Path('configs')
        config_folder.mkdir(exist_ok=True)

        snapshot_folder = Path('configs/snapshots')
        snapshot_folder.mkdir(exist_ok=True)

        config_file = config_folder / 'candidate_config.xml'
        config_file.write_text(config_xml)

        snapshot_file = snapshot_folder / f'snapshot_{timestamp}.xml' 
        snapshot_file.write_text(config_xml)

        print(f"✅Configuration saved to: {config_file}")
        print(f"✅Snapshot saved to: {snapshot_file}")
        return 0
    

    except Exception as e:
        print(f"❌Export failed: {str(e)}", file=sys.stderr)
        return 1
    

def main():
    parser = argparse.ArgumentParser(description='Export Panorama cadidate config')
    parser.add_argument('--force', action = 'store_true', help='Force export even if no changes detected ')
    args = parser.parse_args()
    result = export_config(force=args.force)
    print(f"Result: {result}")
    sys.exit(result)
if __name__ == '__main__':
    main()