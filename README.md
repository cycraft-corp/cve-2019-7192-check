# QNAP Pre-Auth Root RCE (CVE-2019-7192 ~ CVE-2019-7195) Checker

Usage:

```
pip install requests
./Checker_for_QNAP_RCE_cve20197192_95.py /path/to/ip-port.txt
```

Example file input:

```
1.2.3.4 8080
2.3.4.5 443
```

This tool takes a list of QNAP NASes' IPs and ports, and it tells if each
device is vulnerable to the following vulnerabilities:

- CVE-2019–7192 (CVSS 9.8)
- CVE-2019–7193 (CVSS 9.8)
- CVE-2019–7194 (CVSS 9.8)
- CVE-2019–7195 (CVSS 9.8)

# Vulnerability

The vulnerabilities can be chained as a pre-auth root RCE, visit the following
links for more details:

- [Write-Up](https://medium.com/@cycraft_corp/fc8af285622e)
- [QNAP's Security Advisory](https://www.qnap.com/zh-tw/security-advisory/nas-201911-25)

# Credit

The vulnerabilities were discovered by Henry Huang from CyCarrier CSIRT, and
he is also the author of this tool.
