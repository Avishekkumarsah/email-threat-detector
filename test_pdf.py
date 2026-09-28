import traceback
import sys
from modules import report, database

try:
    scans = database.get_all_scans()
    if scans:
        res = report.generate_report(scans[0]['id'])
        print('SUCCESS:', res)
    else:
        print('No scans found')
except Exception as e:
    traceback.print_exc()
