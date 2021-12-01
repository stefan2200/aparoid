"""
Module to extract a list of android versions from Wikipedia
"""
import re
import json
import requests

URL = "https://en.wikipedia.org/wiki/Android_version_history"
result = requests.get(url=URL)

output_versions = {}
version_table = result.text.split('<table class="wikitable">')[1].split('</table>')[0]
get_list = re.findall('(?s)(<tr>.+?</tr>)', version_table)
for version_text in get_list[1:]:
    list_group_data = [x.strip() for x in re.findall('(?s)<td.*?>(.+?)</td>', version_text)]
    if len(list_group_data) != 7:
        continue
    version_name = list_group_data[0]
    if "<a" in version_name:
        version_name = version_name.split(">")[1].split("<")[0]
    security_support = list_group_data[4] != "No"
    api_level = list_group_data[5]
    output_versions[api_level] = {"name": version_name, "supported": security_support}

with open("android_versions.json", "w", encoding="utf-8") as write_versions:
    json.dump(output_versions, fp=write_versions, indent=4)

print(f"Wrote {len(output_versions)} Android versions to output files")
