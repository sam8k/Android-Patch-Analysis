import requests
from bs4 import BeautifulSoup
import pandas as pd
import re


#Todo Add Section (eg Media Framework)
#Todo Remove two rows for same CVE bug

srno = []
cve = []
severity = []
upaosp = []
ref = []

# This is used to store the patch Id of the respective android patch
patchId = []

# This stores the patch date for Excel file
pat = []

# This is used for storing all the patch dates
patches = []

# android_version = input("Enter The Android Version\nEnter 'all' for all android version\n:")
android_version = input("Enter the android version\n>>")

url = 'https://source.android.com/security/bulletin/2015-08-01'
page = requests.get(url)
soup = BeautifulSoup(page.content, 'html5lib')
links = soup.findAll('a', href=True)
for link in links:
    link = link['href']
    if re.match("/security/bulletin/\d\d\d\d-\d\d-\d\d", link):
        date = link.split("/")[-1]
        patches.append(date)

for patch in patches:
    url = 'https://source.android.com/security/bulletin/' + patch
    page = requests.get(url)
    soup = BeautifulSoup(page.content, 'html5lib')

    tables = soup.findAll("table")
    print("[+] Scanned CVEs for Patch : " + patch)

    for table in tables:
        tbody = table.find("tbody")
        trs = tbody.findAll("tr")
        tr0 = trs[0]
        ths = tr0.findAll("th")
        isFound = False
        for th in ths:
            th = th.string
            if th == "Updated AOSP versions":
                isFound = True
                break
        if isFound:
            le = len(trs)
            for i in range(1, le):
                tr = trs[i]
                url = " "

                try:
                    cve_id = tr.findAll("td")[0].string
                    if cve_id is None:
                        cve_id = str(tr.findAll("td")[0])
                        cve_id = re.search("CVE-\d{4}-\d{4,7}", cve_id)
                        try:
                            cve_id = cve_id.group().strip()
                        except AttributeError:
                            print(tr.findAll("td")[0])
                            cve_id = "Check the Google WebSite"
                    ref_link = tr.findAll("td")[1]
                    links = ref_link.findAll('a')
                    if links is not None:
                        pID = links[0].string
                        for link in links:
                            if link.get('href') == '#asterisk':
                                url = "NA"
                                continue
                            url = url + "\n" + link.get("href")
                    ty = tr.findAll("td")[2].string
                    sev = tr.findAll("td")[3].string
                    if "All" in sev:
                        sev = tr.findAll("td")[2].string
                    up = tr.findAll("td")[4].string
                except IndexError:
                    cve_id = "Previous CVE Id"
                    ref_link = "Previous Ref Link"
                    ty = tr.findAll("td")[0].string
                    sev = tr.findAll("td")[1].string
                    up = tr.findAll("td")[2].string

                if android_version in up:
                    cve.append(cve_id)
                    ref.append(url)
                    patchId.append(pID)
                    severity.append(sev)
                    upaosp.append(up)
                    pat.append(patch)


dic = {"Patch": pat, "CVE": cve, "Severity": severity, "Update": upaosp, "Patch ID": patchId, "Reference": ref}
print("[+] New Excel File Created")
df = pd.DataFrame(dic)
df.to_excel('Google_AOSP_Patch_Details.xlsx')
