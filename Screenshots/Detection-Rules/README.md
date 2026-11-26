# Detection Rules – Splunk SPL Queries

This folder contains the SPL queries I used to investigate Windows authentication events and detect repeated failed login attempts.

## 1. Failed Login Attempts (Event ID 4625)

This search finds failed Windows login attempts.

```spl
index=winevenlog "4625"
```

## 2. Successful Login Attempts (Event ID 4624)

This search finds successful Windows login events.

```spl
index=winevenlog "4624"
```

## 3. Failed Login Attempts by Source IP

This search extracts source IP addresses from failed login events and counts the attempts from each address.

```spl
index=winevenlog "4625"
| rex field=_raw "Data Name='IpAddress'>\s*(?<src_ip>[^<]+)"
| eval src_ip=trim(src_ip)
| stats count as failed_attempts by src_ip
| sort - failed_attempts
```

## 4. Brute-Force Detection – Five-Minute Window

This search detects three or more failed login attempts from the same source IP within a rolling five-minute window.

```spl
index=winevenlog "4625"
| rex field=_raw "Data Name='IpAddress'>\s*(?<src_ip>[^<]+)"
| eval src_ip=trim(src_ip)
| sort 0 _time
| streamstats time_window=5m count as failed_attempts by host, src_ip
| where failed_attempts >= 3
| table _time host src_ip failed_attempts
```

## Detection Logic

- **Event ID 4625:** Failed logon attempt.
- **Event ID 4624:** Successful logon.
- **Source IP:** Helps identify where failed login attempts originated.
- **Threshold:** Three or more failed attempts.
- **Time Window:** Five minutes.
- **Detection Method:** Rolling time window using `streamstats`.

## Note

I tested the brute-force detection by generating controlled failed login attempts in my Windows lab environment. This was a lab simulation, not a real attack.
