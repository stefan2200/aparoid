"""
Module for reading and parsing android permissions
"""

import re
import json
import requests

res = requests.get("https://developer.android.com/reference/android/Manifest.permission")

constants = res.text.split('<table id="constants"')[1].split("</table>")[0]
get_list = re.findall(r'(?s)<tr(.+?)</tr>', constants)[1:]

permissions = {}

for perm in get_list:
    perm_key = re.search(r'Manifest\.permission#(.+?)"', perm)
    perm_value = re.search(r'(?s)</code>\s*<p>(.+?)</td>', perm)
    perm_text = perm_value.group(1)
    perm_text = re.sub(r'<[^>]*>', '', perm_text).strip()
    perm_text = perm_text.replace("\n", " ").replace("\t", " ")
    perm_text = perm_text.replace("Protection level: dangerous", '')
    perm_text = perm_text.replace("Protection level: normal", "")
    perm_text = re.sub(r'\s{2,}', ' ', perm_text)
    permissions[perm_key.group(1)] = perm_text

with open('android_permissions.json', 'w', encoding="utf-8") as write_file:
    json.dump(permissions, fp=write_file, indent=4)
    print(f"Wrote {len(permissions)} entries into android_permissions.json")
