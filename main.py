import re, requests, platform, subprocess, socket, pathlib, html, webbrowser, base64
from tabulate import tabulate
from datetime import date
import matplotlib.pyplot as plt
from io import BytesIO

max_score = 0
user_score = 0

pros_outmsg = [['Impact','Type','Description', 'More Information']]
cons_outmsg = [['Impact','Type','Description', 'More Information']]

def windows10_version():
    response = requests.get("https://learn.microsoft.com/en-us/windows/release-health/release-information")
    html = response.text
    matches = re.findall(r"(\d+)\.\d+", html)
    return matches

def windows11_version():
    response = requests.get("https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information")
    html = response.text
    matches = re.findall(r"(\d+)\.\d+", html)
    return matches



def get_account_info():
    result = subprocess.run('net accounts', stdout=subprocess.PIPE)
    account_info = result.stdout.decode('utf-8')
    values = re.findall(r":\s+(.*)\r", account_info)
    return values

def get_defender_info():
    result = subprocess.run('powershell -command "Get-MpComputerStatus"', stdout=subprocess.PIPE)
    result = result.stdout.decode('utf-8')
    values = re.findall(r":\s+(.*)\r", result)
    return values

def scan_ports():

    open_ports = []
    closed_ports = []
    target = '127.0.0.1'
    # Lst of ports from https://securitytrails.com/blog/top-scanned-ports, plus port 20 and and 137
    port_range = [20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 137, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        for i in port_range:
            if s.connect_ex((target, i)) == 0:
                open_ports.append(i)
            else:
                closed_ports.append(i)
    s.close()
    return(open_ports, closed_ports, port_range)

supported_windows_versions = []
# Windows 10 supported versions
supported_windows_versions.append(windows10_version()[3])
supported_windows_versions.append(windows10_version()[4])
supported_windows_versions.append(windows10_version()[5])
# Windows 10 Supported Versions
supported_windows_versions.append(windows11_version()[3])
supported_windows_versions.append(windows11_version()[4])

if platform.system() == 'Windows':
    max_score += 10
    version = platform.win32_ver()[1].split('.')[2]
    for supported_version in supported_windows_versions:
        if version == supported_version:
            user_score += 10
            pros_outmsg.append(['+10',
                                   'Update: Operating System<br>',
                                   'You are running a supported version of Windows!',
                                   'Read more about why it is important to update Windows here: <a href="{0}">{0}</a>'.format('https://www.zunesis.com/why-install-windows-updates/')
                                   ])
            break
        else:
            continue
    if version != supported_version:
        cons_outmsg.append(['-10',
                               'Update: Operating System',
                               'Your version of Windows is Outdated, consider updating your version of Windows to the newest release. This will help reduce the probability of OS vulnerabilities being exploited on your system.',
                               'Read more about why it is important to update Windows here: <a href="https://www.zunesis.com/why-install-windows-updates/">https://www.zunesis.com/why-install-windows-updates/</a>'
                               ])
else:
    print('This script only works for Windows systems.')



matches = get_account_info()
max_pass_age = matches[2]
min_pass_len = matches[3]
lockout_threshold = matches[5]
lockout_duration = matches[6]

max_score += 5
if (0 < int(max_pass_age) <= 90):
    user_score += 5
    pros_outmsg.append(['+5',
                        'Policy: Maximum Password Age',
                        'Your maximum password age is set to between 1 and 90 days. The best practice is to set this value between 30 and 90 days to prevent using an insecure or compromised password for an extended amount of time.',
                        'Read more about the importance password age here: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/')
                        ])
elif max_pass_age == 'UNLIMITED':
    cons_outmsg.append(['-5',
                    'Policy: Maximum Password Age',
                    'Your maximum password age is set to either a vaule less than 1 or greater than  90 days. The best practice is to set this value between 30 and 90 days to prevent using an insecure or compromised password for an extended amount of time.',
                    'Go here to learn how to change this policy on your computer: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age')
                    ])
else:
    cons_outmsg.append(['-5',
                    'Policy: Maximum Password Age',
                    'Your maximum password age is set to either a vaule less than 1 or greater than  90 days. The best practice is to set this value between 30 and 90 days to prevent using an insecure or compromised password for an extended amount of time.',
                    'Go here to learn how to change this policy on your computer: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age')
                    ])

max_score += 7
if int(min_pass_len) >= 8:
    pass_len_score = int(min_pass_len)-7
    user_score += pass_len_score
    pros_outmsg.append(['+{0}'.format(pass_len_score),
                        'Policy: Minimum Password Length',
                        'Your minimum password length policy is set to a value of 8 characters or more. Best practice is to use a password with a length of 8 or more characters to prevent cyber attacks, the longer the better.',
                        'Read more about password length policy and best Practice here: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-length')
                        ])
else:
    cons_outmsg.append(['-7',
                        'Policy: Minimum Password Length',
                        'Your minimum password length policy is either disabled or set to a value less than 7 characters. Best practice is to use a password with a length of 8 or more characters to prevent cyber attacks, the longer the better.',
                        'Go here to learn how to change this policy on your computer: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-length')
                        ])

max_score += 10
if lockout_threshold == 'Never':
    cons_outmsg.append(['-5',
                        'Policy: Lockout threshold',
                        'Your account lockout threshold policy is set to never, meaning an attacker could guess passwords indefinitiely until they find a password that will let them log into your machine. Best practice is to use a lockout threshold of 10, but there is no one-size-fits-all solution.',
                        'Go here to learn how to change this policy on your computer: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold')
                        ])
elif (0 < int(lockout_threshold) <= 20):
    user_score += 5
    pros_outmsg.append(['+5',
                        'Policy: Lockout threshold',
                        'Your account lockout threshold policy is set to a value between 1 and 20, meaning that an attacker will be locked our for some period of time if they repeatedly, incorrectly guess a login. Best practice is to use a lockout threshold of 10, but there is no one-size-fits-all solution.',
                        'Read more about Account Lockout Threshold Policy here: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold')
                        ])
    if int(lockout_duration) == 0:
        user_score += 5
        pros_outmsg.append(['+5',
                        'Policy: Lockout Duration',
                        'Your account lockout duration policy is set to 0, meaning that once the lockout threshold has been met, an account will be locked out until an admin unlocks it.',
                        'Read more about Account Lockout Duration Policy here: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration')
                        ])
    elif 0 < int(lockout_duration) < 15:
        user_score += 2
        pros_outmsg.append(['+2',
                        'Policy: Lockout Duration',
                        'Your account lockout duration policy is set to a value between 1 and 15, meaning that once the lockout threshold has been met, an account will be locked out from 1 to 15 minutes depending on the policy. Best practice is to set this value to 15 minutes, your score is 2 out of 5.',
                        'Learn how to change this policy here Policy here: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration')
                        ])
    elif int(lockout_duration) >= 15:
        user_score += 5
        pros_outmsg.append(['+2',
                        'Policy: Lockout Duration',
                        'Your account lockout duration policy is set to a value of 15 minutes or greater, meaning that once the lockout threshold has been met, an account will be locked out for 15+ minutes depending on the policy. Best practice is to set this value to at least 15 minutes.',
                        'Read more about Account Lockout Duration policy here: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration')
                        ])
elif (int(lockout_threshold) > 20):
    if int(lockout_duration) == 0:
        user_score += 5
        pros_outmsg.append(['+5',
                        'Policy: Lockout Duration',
                        'Your account lockout duration policy is set to 0, meaning that once the lockout threshold has been met, an account will be locked out until an admin unlocks it.',
                        'Read more about Account Lockout Duration Policy here: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration')
                        ])
    elif 0 < int(lockout_duration) < 15:
        user_score += 2
        pros_outmsg.append(['+2',
                        'Policy: Lockout Duration',
                        'Your account lockout duration policy is set to a value between 1 and 15, meaning that once the lockout threshold has been met, an account will be locked out from 1 to 15 minutes depending on the policy. Best practice is to set this value to 15 minutes, your score is 2 out of 5.',
                        'Learn how to change this policy here Policy here: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration')
                        ])
    elif int(lockout_duration) >= 15:
        user_score += 5
        pros_outmsg.append(['+2',
                        'Policy: Lockout Duration',
                        'Your account lockout duration policy is set to a value of 15 minutes or greater, meaning that once the lockout threshold has been met, an account will be locked out for 15+ minutes depending on the policy. Best practice is to set this value to at least 15 minutes.',
                        'Read more about Account Lockout Duration policy here: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration')
                        ])

else:
    cons_outmsg.append(['-5',
                        'Policy: Lockout threshold',
                        'Your account lockout threshold policy is set to a value greater than 20, meaning that an attacker will be locked our for some period of time if they incorrectly the password to your system 21 or more times. Best practice is to use a lockout threshold of 10, but there is no one-size-fits-all solution.',
                        'Go here to learn how to change this policy on your computer: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold')
                        ])

defender_vals = get_defender_info()
anti_mal = defender_vals[3]
anti_spy = defender_vals[5]
anti_virus = defender_vals[9]
behavioral = defender_vals[13]
out_of_date = defender_vals[16]
realtime = defender_vals[41]

max_score += 10
if (anti_mal == 'True') and (anti_spy == 'True') and (anti_virus == 'True'):
    user_score += 10
    pros_outmsg.append(['+10',
                        'Windows Security: Core Protections',
                        'Windows Security appears to be active and running with anti-malware, anti-spyware, and anti-virus all enabled. This is best practice and will help prevent your computer and data from becoming compromised.',
                        'Read more about Windows Security here: <a href="{0}">{0}</a>'.format('https://support.microsoft.com/en-us/windows/stay-protected-with-windows-security-2ae0363d-0ada-c064-8b56-6a39afb6a963')
                        ])
else:
    cons_outmsg.append(['-10',
                        'Windows Security: Core Protections',
                        'Microsoft Security is either not running, not enabled, or running without one or more core protections being active. Running Microsoft Defender with the anti-malware, anti-spyware, and anti-virus functionalities enabled will help prevent malware threats from compromising your computer.',
                        'Go here to learn how to configure Windows Security with anti-malware: <a href="{0}">{0}</a>'.format('https://support.microsoft.com/en-us/windows/virus-threat-protection-in-windows-security-1362f4cd-d71a-b52a-0b66-c2820032b65e')
                        ])

max_score += 10
if behavioral == 'True':
    user_score += 10
    pros_outmsg.append(['+10',
                        'Windows Security: Behavioral Monitoring',
                        'Windows Security appears to be active and running with behavioral monitoring all enabled. This is best practice and will help prevent your computer and data from becoming compromised.',
                        'Read more about why behavioral monitoring is important here: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/behavioral-blocking-containment?view=o365-worldwide')
                        ])
else:
    cons_outmsg.append(['-10',
                        'Windows Security: Behavioral Monitoring',
                        'Microsoft Security does not have behavioral monitoring enabled, meanining that your system is vulnerable to attack / compromise from fileless malware, human-operated attacks, and highly-advanced malware threats. Running Windows Security with behavioral monitoring enabled will help prevent these types of malware from compromising your computer and data.',
                        'Go here to learn how to configure Windows Security with behavioral monitoring: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus?view=o365-worldwide')
                        ])

max_score += 10
if realtime == 'True':
    user_score += 10
    pros_outmsg.append(['+10',
                        'Windows Security: Real-Time Protection',
                        'Windows Security appears to be active and running with real-time protection enabled. This is best practice and means that Windows Security is working to keep your computer and your data safe.',
                        'Read more about why real-time protection is important here: <a href="{0}">{0}</a>'.format('https://www.cyber.gov.au/acsc/view-all-content/guidance/turn-real-time-protection-windows-10')
                        ])
else:
    cons_outmsg.append(['-10',
                        'Windows Security: Real-Time Protection',
                        'Windows Security does not have real-time protection enabled, this will leave you exposed to malicious files and threats between anti-virus / anti-malware scans. Running Windows Security with real-time protection is best practice to keep your computer and your data safe.',
                        'Go here to learn how to configure Windows Security with always-on protection: <a href="{0}">{0}</a>'.format('https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus?view=o365-worldwide')
                        ])

max_score += 10
if out_of_date == 'False':
    user_score += 10
    pros_outmsg.append(['+10',
                        'Windows Security: Update',
                        'Windows Security, its signatures, and its detections are all up to date. This is best practice and means that Windows Security is working to keep your computer and your data safe by using the more current information it has access to.',
                        'Read more about why it is important to keep Windows Security up-to-date: <a href="{0}">{0}</a>'.format('https://ecmanagedit.com/importance-windows-updates/')
                        ])
else:
    cons_outmsg.append(['-10',
                        'Windows Security: Update',
                        "Windows Security, its signatures, and/or it's detections are out of date and need to be updated. Update Windows Security immediately to ensure that your computer and data remain as safe as possible.",
                        'Go here to learn how to update Windows Security: <a href="{0}">{0}</a>'.format('https://support.microsoft.com/en-us/windows/update-windows-security-signatures-726d462d-b2a8-5bb2-8a9e-5d5871b06e05')
                        ])

open_ports, closed_ports, port_range = scan_ports()
max_score += len(port_range)*5
user_score += len(closed_ports)*5
if len(closed_ports) != 0:
    pros_outmsg.append(['+{0}'.format(len(closed_ports)*5),
                        'Ports: Closed Ports',
                        'Your computer has {0} out of {1} commonly abused ports closed. It is best practice to close unused and unneeded ports at all times, as vulnerable ports that are left open can be used to compromise a system.'.format(len(closed_ports), len(port_range)),
                        'Read more about the importance of closing vulnerable ports: <a href="{0}">{0}</a>'.format('https://blog.netwrix.com/2022/08/16/open-network-ports')
                        ])

if len(open_ports) != 0:
    for port in open_ports:
        port_url = 'https://www.speedguide.net/portscan.php?port={0}&tcp=1&udp=1'.format(port)
        generic_url = 'https://www.manageengine.com/vulnerability-management/misconfiguration/windows-firewall/how-to-close-port-135-udp-tcp-disabling-dcom-service-control-manager.html'
        cons_outmsg.append(['-5',
                        'Ports: Open Ports',
                        'Port {0} is currently open on your system. This port has been idenfitied as a commonly abused port. If you are not hosting or using any services that utilize port {0}, then please close it.'.format(port),
                        'Go here to learn about the vulnerabilities and services associated with port {0} <a href="{0}">{0}</a><br>Go here to learn how to close a port in Windows: <a href="{1}">{1}</a>'.format(port_url, generic_url)
                        ])

user_score_percent = round((user_score/max_score)*100, 2)
if user_score_percent == 100:
    user_grade = "A+"
elif 90 <= user_score_percent < 100:
    user_grade = "A"
elif 85 <= user_score_percent < 90:
    user_grade = "AB"
elif 80 <= user_score_percent < 85:
    user_grade = "B"
elif 75 <= user_score_percent < 80:
    user_grade = "BC"
elif 70 <= user_score_percent < 75:
    user_grade = "C"
elif 65 <= user_score_percent < 70:
    user_grade = "CD"
elif 60 <= user_score_percent < 65:
    user_grade = "D"
else:
    user_grade = "F"

html_template = """
<!DOCTYPE html>
<html>
<head>
	<title>Security Report Card</title>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
    {6}
    </style>
</head>
<body>
    <div>
    <img src="data:image/png;base64,{7}" width="426" height="320" style="float:right">
	<h1 style="text-align:center;">Security Report Card</h1>
    <p style="text-align:center;">{8}</p>
	<h3>Security Score:&emsp;{0}&sol;{1}<br>Overall Grade:&emsp;{3}&emsp;({2}%)</h3>
    <p>You earned {0} points out of {1} total points. To increase your score, please read through the report below and refer to any included URLs if you wish to increase your score.</p>
    </div>
    <div>
    <br><br><br>
	<font color="#2dc937"><h2>Positive Security Practices</h2></font>
    {4}
    <font color="#cc3232"><h2>Negative Security Practices</h2></font>
    {5}
    </div>
</body>
</html>
"""

today = date.today()
today1 = today.strftime("%m_%d_%Y")
today2 = today.strftime("%m/%d/%Y")

current_path = pathlib.Path().resolve()
output_html_path = str(current_path) + '//Report_Card_'+str(today1)+'.html'

pros_html = html.unescape(tabulate(pros_outmsg, tablefmt='html', headers='firstrow'))
cons_html = html.unescape(tabulate(cons_outmsg, tablefmt='html', headers='firstrow'))
style = 'body { font-family: Verdana, sans-serif;padding: 5px;} th, td { padding: 5px; text-align: center;} table, th, td {border: 1px solid black;} img {position: relative;} h1 {text-align: center;}'

negative_score = max_score-user_score
scores = [user_score, negative_score]
labels = ['Good', 'Bad']
colors = ['#2dc937', '#cc3232']
plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.weight"] = "bold"
plt.rcParams["font.size"] = 20
plt.pie(scores, labels = labels, colors = colors, autopct='%.2f%%')

fig = plt.gcf()

plt.draw()
plt.figure()
save_plt = BytesIO()
fig.savefig(save_plt, format='png')
save_plt.seek(0)
encoded = base64.b64encode(save_plt.read()).decode()

final_outmsg_html = html_template.format(user_score, max_score, user_score_percent, user_grade, pros_html, cons_html, style, encoded, today2)

with open(output_html_path, 'w') as out:
    out.write(final_outmsg_html)

webbrowser.open(output_html_path)
