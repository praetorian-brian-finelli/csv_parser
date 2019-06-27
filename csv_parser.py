#!/usr/bin/env python
#Brian Finelli - Praetorian

import pandas as pd
import sys

def printHelp():
    print("./csv_parser.py nessus.csv (-all) (-versions)")
    print("\t-all prints all nessus findings with usable host IP tables (otherwise only prints findings that have a vkb mapped)")
    print("\t-versions creates a second file formatted to use with missing security patches template")
    print("\t-print will print all vulnerability titles from the nessus file")
    print("\t-help prints this message")

findings_dict = {"SSL Weak Cipher Suites Supported": "weak_ssl_ciphers_supported.md",
        "F5 BIG-IP Cookie Remote Information Disclosure": "f5_big_ip_cookie_internal_address_and_host_name_disclosure.md",
        "Internet Key Exchange (IKE) Aggressive Mode with Pre-Shared Key": "internet_key_exchange_ike_aggressive_mode_with_pre_shared_key.md",
        "Microsoft Windows Server 2003 Unsupported Installation Detection": "windows_2003_servers_identified.md",
        "SSH Server CBC Mode Ciphers Enabled": "ssh_server_cbc_mode_ciphers_enabled.md",
        "SSH Weak Algorithms Supported": "ssh_weak_mac_algorithms_enabled.md",
        "SSH Weak MAC Algorithms Enabled": "ssh_weak_mac_algorithms_enabled.md",
        "SSL Certificate Cannot Be Trusted": "invalid_server_certificates.md",
        "SSL Certificate Expiry": "expired_ssl_certificate.md",
        "SSL Certificate Signed Using Weak Hashing Algorithm": "server_certificate_signed_using_sha_1_algorithm.md or server_certificate_signed_using_md5_algorithm.md",
        "SSL Medium Strength Cipher Suites Supported (SWEET32)": "3des_ciphersuites_supported.md",
        "SSL RC4 Cipher Suites Supported (Bar Mitzvah)": "ssl_rc4_ciphers_enabled.md",
        "SSL Self-Signed Certificate": "invalid_server_certificates.md",
        "SSL Version 2 and 3 Protocol Detection": "outdated_ssl_versions_enabled.md",
        "SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)": "weak_ssl_tls_diffie_hellman_parameters_logjam.md",
        "SSL/TLS EXPORT_DHE <= 512-bit Export Cipher Suites Supported (Logjam)": "weak_ssl_tls_diffie_hellman_parameters_logjam.md",
        "Microsoft Windows Remote Desktop Protocol Server Man-in-the-Middle Weakness": "microsoft_windows_rdp_server_mitm.md",
        "Microsoft Windows SMBv1 Multiple Vulnerabilities": "smbv1_enabled.md",
        "Microsoft Windows XP Unsupported Installation Detection": "windows_xp_systems_identified.md",
        "SMB Signing not required": "smb_signing_not_enforced.md",
        "Terminal Services Doesn't Use Network Level Authentication (NLA) Only": "terminal_services_without_nla.md",
        "Terminal Services Encryption Level is Medium or Low": "terminal_services_encryption_level_medium_low.md",
        "Terminal Services Encryption Level is not FIPS-140 Compliant": "terminal_services_encryption_level_medium_low.md",
        "Web Server Directory Traversal Arbitrary File Access": "path_traversal.md",
        "MS17-010: Security Update for Microsoft Windows SMB Server (4013389) (ETERNALBLUE) (ETERNALCHAMPION) (ETERNALROMANCE) (ETERNALSYNERGY) (WannaCry) (EternalRocks) (Petya) (uncredentialed check)": "missing_ms17_010_security_patch.md",
        "Apache Tomcat Default Files": "default_documents.md"
        }

if "-help" in sys.argv or "-h" in sys.argv or len(sys.argv) < 2:
    printHelp()
    exit()

try:
    f=pd.read_csv(sys.argv[1], sep=",")
except IOError:
    print ("Could not read file:", sys.argv[1])
    printHelp()
    sys.exit()

#make extra columns for formatting later on
f['bullet'] = '-'
f['Protocol'] = '(' + f['Protocol'].astype(str)
f['Port'] = '/' + f['Port'].astype(str)
f['Port'] = f['Port'].astype(str) + ')'
f['Port_combined'] = f['Protocol'] + f['Port'] #combine protocol and port eg (tcp/443)
keep_col = ['bullet', 'Name', 'Host', 'Port_combined']
f = f[keep_col]
f = f.sort_values(by=['Name'])
vuln_column = f.Name.unique()
vuln_column = [vuln.replace('_', '-') for vuln in vuln_column]

if "-print" in sys.argv:
    for i in vuln_column:
        print(i) #print all unique vuln column values

#list for missing software patches finding, just looks for "<" in vuln title
if "-versions" in sys.argv:
    #software = ["Apache", "OpenSSL", "PHP", "Dropbear"]
    out = open("versions_output", "w+")
    out.write("% BeginTable(targets) %\ncolumns: 3\nhosts_with_header:\n")
    for value in vuln_column:
        #if any(type in value for type in software):
        if ("< " in value):
            f1 = f.loc[f['Name'] == value]
            keep_col = ['bullet', 'Host', 'Port_combined']
            f1 = f1[keep_col]
            f1 = f1.sort_values(by=['Host'])
            csv = f1.to_csv(header=False, index=False, sep=" ")
            csv = csv.replace("-", "     -")
            out.write(" - header:\n" + "   - name: " + value + "\n   - hosts:\n")
            out.write(csv)
    out.write("% EndTable(targets) %")
    out.close()

out = open("csv_output", "w+")
for value in vuln_column:
    f1 = f.loc[f['Name'] == value]
    keep_col = ['bullet', 'Host', 'Port_combined']
    f1 = f1[keep_col]
    f1 = f1.sort_values(by=['Host'])
    csv = f1.to_csv(header=False, index=False, sep=" ")
    csv = csv.replace("-", " -")
    if value in findings_dict:
        out.write("Title: " + value + "\n" + "suggested VKB template: " + findings_dict[value] + "\n% BeginTable(targets) %\ncolumns: 2\ngeneric_hosts:\n" + csv + "% EndTable(targets) %\n\n\n")
    elif "-all" in sys.argv:
        out.write("Title: " + value + "\n% BeginTable(targets) %\ncolumns: 2\ngeneric_hosts:\n" + csv + "% EndTable(targets) %\n\n\n")
out.close()
