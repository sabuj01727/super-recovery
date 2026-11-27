#!/usr/bin/env python3
"""Recovery Toolkit launcher - run:  python toolkit.py"""
import backup_finder
import carver
import adb_extract

MENU = """
############ RECOVERY TOOLKIT ############
 1) Backup Finder      - scan PC + cloud checklist
 2) ADB Extractor      - contacts, SMS, call log, apps, /sdcard from a connected phone
 3) File Carver        - recover deleted photos/videos/PDF/DB from SD card / image / drive
 0) Exit
"""

while True:
    print(MENU)
    c = input("Choose: ").strip()
    try:
        if c == "1":
            backup_finder.main()
        elif c == "2":
            adb_extract.run()
        elif c == "3":
            carver.main()
        elif c == "0":
            break
    except KeyboardInterrupt:
        print("\n(stopped)")
