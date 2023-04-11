import re, requests, platform, subprocess, socket, pathlib



max_score = 0
user_score = 0

pros_outmsg = 'Positive Security Practices\n\n'
cons_outmsg = 'Bad Security Practices\n\n'

def windows_version():
    response = requests.get("https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information")
    html = response.text
    matches = re.findall(r"(\d+\.\d+)", html)
    if matches:
        return matches[0]
    else:
        return None

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

newest_version = windows_version()

if platform.system() == 'Windows':
    max_score += 10
    version = platform.release()
    if version < newest_version:
        cons_outmsg = cons_outmsg + "-10\tUpdates - Your version of Windows is Outdated, consider updating your version of Windows to the newest release. This will help reduce the probability of OS vulnerabilities being exploited on your system.\n\tRead more about why it is important to update Windows here: https://www.zunesis.com/why-install-windows-updates/\n\n"
    else:
        user_score += 10
        pros_outmsg = pros_outmsg + "+10\tUpdates - You are running the current version of Windows!\n\tRead more about why it is important to update Windows here: https://www.zunesis.com/why-install-windows-updates/\n\n"
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
    pros_outmsg = pros_outmsg + '+5\tPolicy: Maximum Password Age - Your maximum password age is set to between 1 and 90 days. The best practice is to set this value between 30 and 90 days to prevent using an insecure or compromised password for an extended amount of time.\n\tRead more about the importance password age here: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age\n\n'
elif max_pass_age == 'UNLIMITED':
    cons_outmsg = cons_outmsg + '-5\tPolicy: Maximum Password Age - Your maximum password age is set to either a vaule less than 1 or greater than  90 days. The best practice is to set this value between 30 and 90 days to prevent using an insecure or compromised password for an extended amount of time.\n\tGo here to learn how to change this policy on your computer: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age\n\n'
else:
    cons_outmsg = cons_outmsg + '-5\tPolicy: Maximum Password Age - Your maximum password age is set to either a vaule less than 1 or greater than  90 days. The best practice is to set this value between 30 and 90 days to prevent using an insecure or compromised password for an extended amount of time.\n\tGo here to learn how to change this policy on your computer: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age\n\n'

max_score += 7
if int(min_pass_len) >= 8:
    pass_len_score = int(min_pass_len)-7
    user_score += pass_len_score
    pros_outmsg = pros_outmsg + '+'+str(pass_len_score)+'\tPolicy: Minimum Password Length - Your minimum password length policy is set to a value of 8 characters or more. Best practice is to use a password with a length of 8 or more characters to prevent cyber attacks, the longer the better.\n\tRead more about password length policy and best Practice here: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-length\n\n'
else:
    cons_outmsg = cons_outmsg + '-7\tPolicy: Minimum Password Length - Your minimum password length policy is either disabled or set to a value less than 7 characters. Best practice is to use a password with a length of 8 or more characters to prevent cyber attacks, the longer the better.\n\tGo here to learn how to change this policy on your computer: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-length\n\n'

    
max_score += 10
if lockout_threshold == 'Never':
    cons_outmsg = cons_outmsg + '-5\tPolicy: Lockout threshold - Your account lockout threshold policy is set to never, meaning an attacker could guess passwords indefinitiely until they find a password that will let them log into your machine. Best practice is to use a lockout threshold of 10, but there is no one-size-fits-all solution.\n\tGo here to learn how to change this policy on your computer: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold\n\n'
elif (0 < int(lockout_threshold) <= 20):
    user_score += 5
    pros_outmsg = pros_outmsg + '+5\tPolicy: Lockout threshold - Your account lockout threshold policy is set to a value between 1 and 20, meaning that an attacker will be locked our for some period of time if they repeatedly, incorrectly guess a login. Best practice is to use a lockout threshold of 10, but there is no one-size-fits-all solution.\n\tRead more about Account Lockout Threshold Policy here: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold\n\n'
    if int(lockout_duration) == 0:
        user_score += 5
        pros_outmsg = pros_outmsg + '+5\tPolicy: Lockout Duration - Your account lockout duration policy is set to 0, meaning that once the lockout threshold has been met, an account will be locked out until an admin unlocks it.\n\tRead more about Account Lockout Duration Policy here: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration\n\n'
    elif 0 < int(lockout_duration) < 15:
        user_score += 2
        pros_outmsg = pros_outmsg + '+2\tPolicy: Lockout Duration - Your account lockout duration policy is set to a value between 1 and 15, meaning that once the lockout threshold has been met, an account will be locked out from 1 to 15 minutes depending on the policy. Best practice is to set this value to 15 minutes, your score is 2 out of 5.\n\tLearn how to change this policy here Policy here: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration\b\b'
    elif int(lockout_duration) >= 15:
        user_score += 5
        pros_outmsg = pros_outmsg + '+2\tPolicy: Lockout Duration - Your account lockout duration policy is set to a value of 15 minutes or greater, meaning that once the lockout threshold has been met, an account will be locked out for 15+ minutes depending on the policy. Best practice is to set this value to at least 15 minutes.\n\tRead more about Account Lockout Duration policy here: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration\n\n'
elif (int(lockout_threshold) > 20):
    if int(lockout_duration) == 0:
        user_score += 5
        pros_outmsg = pros_outmsg + '+5\tPolicy: Lockout Duration - Your account lockout duration policy is set to 0, meaning that once the lockout threshold has been met, an account will be locked out until an admin unlocks it.\n\tRead more about Account Lockout Duration Policy here: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration\n\n'
    elif 0 < int(lockout_duration) < 15:
        user_score += 2
        pros_outmsg = pros_outmsg + '+2\tPolicy: Lockout Duration - Your account lockout duration policy is set to a value between 1 and 15, meaning that once the lockout threshold has been met, an account will be locked out from 1 to 15 minutes depending on the policy. Best practice is to set this value to 15 minutes, your score is 2 out of 5.\n\tLearn how to change this policy here Policy here: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration\b\b'
    elif int(lockout_duration) >= 15:
        user_score += 5
        pros_outmsg = pros_outmsg + '+2\tPolicy: Lockout Duration - Your account lockout duration policy is set to a value of 15 minutes or greater, meaning that once the lockout threshold has been met, an account will be locked out for 15+ minutes depending on the policy. Best practice is to set this value to at least 15 minutes.\n\tRead more about Account Lockout Duration policy here: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration\n\n'
        
else:
    cons_outmsg = cons_outmsg + '-5\tPolicy: Lockout threshold - Your account lockout threshold policy is set to a value greater than 20, meaning that an attacker will be locked our for some period of time if they incorrectly the password to your system 21 or more times. Best practice is to use a lockout threshold of 10, but there is no one-size-fits-all solution.\n\tGo here to learn how to change this policy on your computer: https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold\n\n'



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
    pros_outmsg = pros_outmsg + '+10\tWindows Security: Core Protections - Windows Security appears to be active and running with anti-malware, anti-spyware, and anti-virus all enabled. This is best practice and will help prevent your computer and data from becoming compromised.\n\tRead more about Windows Security here: https://support.microsoft.com/en-us/windows/stay-protected-with-windows-security-2ae0363d-0ada-c064-8b56-6a39afb6a963\n\n'
else:
    cons_outmsg = cons_outmsg + '-10\tWindows Security: Core Protections - Microsoft Security is either not running, not enabled, or running without one or more core protections being active. Running Microsoft Defender with the anti-malware, anti-spyware, and anti-virus functionalities enabled will help prevent malware threats from compromising your computer.\n\tGo here to learn how to configure Windows Security with anti-malware: https://support.microsoft.com/en-us/windows/virus-threat-protection-in-windows-security-1362f4cd-d71a-b52a-0b66-c2820032b65e\n\n'

max_score += 10   
if behavioral == 'True':
    user_score += 10
    pros_outmsg = pros_outmsg + '+10\tWindows Security: Behavioral Monitoring - Windows Security appears to be active and running with behavioral monitoring all enabled. This is best practice and will help prevent your computer and data from becoming compromised.\n\tRead more about why behavioral monitoring is important here:  https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/behavioral-blocking-containment?view=o365-worldwide\n\n'
else:
    cons_outmsg = cons_outmsg + '-10\tWindows Security: Behavioral Monitoring - Microsoft Security does not have behavioral monitoring enabled, meanining that your system is vulnerable to attack / compromise from fileless malware, human-operated attacks, and highly-advanced malware threats. Running Windows Security with behavioral monitoring enabled will help prevent these types of malware from compromising your computer and data.\n\tGo here to learn how to configure Windows Security with behavioral monitoring:  https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus?view=o365-worldwide\n\n'

max_score += 10
if realtime == 'True':
    user_score += 10
    pros_outmsg = pros_outmsg + '+10\tWindows Security: Real-Time Protection - Windows Security appears to be active and running with real-time protection enabled. This is best practice and means that Windows Security is working to keep your computer and your data safe.\n\tRead more about why real-time protection is important here:  https://www.cyber.gov.au/acsc/view-all-content/guidance/turn-real-time-protection-windows-10\n\n'
else:
    cons_outmsg = cons_outmsg + '-10\tWindows Security: Real-Time Protection - Windows Security does not have real-time protection enabled, this will leave you exposed to malicious files and threats between anti-virus / anti-malware scans. Running Windows Security with real-time protection is best practice to keep your computer and your data safe.\n\tGo here to learn how to configure Windows Security with always-on protection:  https://learn.microsoft.com/en-us/microsoft-365/security/defender-endpoint/configure-real-time-protection-microsoft-defender-antivirus?view=o365-worldwide\n\n'

max_score += 10
if out_of_date == 'False':
    user_score += 10
    pros_outmsg = pros_outmsg + '+10\tWindows Security: Update - Windows Security, its signatures, and its detections are all up to date. This is best practice and means that Windows Security is working to keep your computer and your data safe by using the more current information it has access to.\n\tRead more about why it is important to keep Windows Security up-to-date:  https://ecmanagedit.com/importance-windows-updates/\n\n'
else:
    cons_outmsg = cons_outmsg + "-10\tWindows Security: Update - Windows Security, its signatures, and/or it's detections are out of date and need to be updated. Update Windows Security immediately to ensure that your computer and data remain as safe as possible.\n\tGo here to learn how to update Windows Security:  https://support.microsoft.com/en-us/windows/update-windows-security-signatures-726d462d-b2a8-5bb2-8a9e-5d5871b06e05\n\n"
   
open_ports, closed_ports, port_range = scan_ports()
max_score += len(port_range)*5
user_score += len(closed_ports)*5
pros_outmsg = pros_outmsg + '+{2}\tPorts: Closed Ports - Your computer has {0} out of {1} commonly abused ports closed. It is best practice to close unused and unneeded ports at all times, as vulnerable ports that are left open can be used to compromise a system.\n\tRead more about the importance of closing vulnerable ports:  https://blog.netwrix.com/2022/08/16/open-network-ports/\n\n'.format(len(closed_ports), len(port_range), len(closed_ports)*5)

for port in open_ports:
    cons_outmsg = cons_outmsg + '-5\tPorts: Open Port - Port {0} is currently open on your system. This port has been idenfitied as a commonly abused port. If you are not hosting or using any services that utilize port {0}, then please close it.\n\tGo here to learn about the vulnerabilities and services associated with port {0}  https://www.speedguide.net/portscan.php?port={0}&tcp=1&udp=1\n\tGo here to learn how to close a port in Windows:  https://www.manageengine.com/vulnerability-management/misconfiguration/windows-firewall/how-to-close-port-135-udp-tcp-disabling-dcom-service-control-manager.html\n\n'.format(port)



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
final_outmsg = "You earned {0} points out of {1} total points. To increase your score, please read through the report below and refer to any included URLs.\nSecurity Score:\t{2}%\nSecurity Grade: {3}\n\n{4}\n\n{5}".format(user_score, max_score, user_score_percent, user_grade, pros_outmsg, cons_outmsg)
print(final_outmsg)


# output_html = open("C:\\Users\\Suleiman JK\\Desktop\\Static_hash\\test","r")