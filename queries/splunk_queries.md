# SOC Dashboard: SSH Brute Force Monitoring (Splunk SPL)

Index: `soc_lab` | Sourcetype: `linux_secure`

These queries use `rex`, so they work without any add-on.

## 1. KPI tiles (single value)

Failed logins:
```
index=soc_lab sourcetype=linux_secure "Failed password" | stats count AS "Failed Logins"
```

Successful logins:
```
index=soc_lab sourcetype=linux_secure "Accepted" | stats count AS "Successful Logins"
```

Unique attacker IPs:
```
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats dc(src_ip) AS "Attacker IPs"
```

Targeted usernames:
```
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "Failed password for (?:invalid user )?(?<user>\S+) from"
| stats dc(user) AS "Usernames Targeted"
```

## 2. Failed logins over time (line chart)
```
index=soc_lab sourcetype=linux_secure "Failed password"
| timechart span=1h count AS "Failed Logins"
```

## 3. Top 10 attacking IPs (bar chart)
```
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count by src_ip
| sort - count
| head 10
```

## 4. Attacker geo map (cluster map)
```
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| iplocation src_ip
| geostats count
```

## 5. Top targeted usernames (bar / pie chart)
```
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "Failed password for (?:invalid user )?(?<user>\S+) from"
| stats count by user
| sort - count
| head 10
```

## 6. Possible compromise: success after many failures (table)
MITRE ATT&CK: T1110 Brute Force
```
index=soc_lab sourcetype=linux_secure ("Failed password" OR "Accepted password")
| rex "(?<outcome>Failed|Accepted) password for (?:invalid user )?(?<user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count(eval(outcome="Failed")) AS failures count(eval(outcome="Accepted")) AS successes by src_ip user
| where failures>=10 AND successes>=1
| sort - failures
```

## 7. Attacks by hour of day (column chart)
```
index=soc_lab sourcetype=linux_secure "Failed password"
| stats count by date_hour
| sort date_hour
```

## 8. Latest suspicious events with severity (table)
```
index=soc_lab sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count AS attempts latest(_time) AS last_seen by src_ip
| eval severity=case(attempts>=300,"Critical", attempts>=100,"High", attempts>=30,"Medium", true(),"Low")
| eval last_seen=strftime(last_seen,"%Y-%m-%d %H:%M:%S")
| sort - attempts
| head 15
```

## Dashboard layout
- Row 1: 4 KPI tiles (queries 1)
- Row 2: Failed logins over time (wide) + Top attacking IPs
- Row 3: Geo map (wide) + Top usernames
- Row 4: Attacks by hour + Success-after-failures table
- Row 5: Severity table (full width)

Tip: set the time range to "All time" (the log covers 7 days) and use Dark theme.
