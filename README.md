# CWP API Python Wrapper

## Usage examples:
```
from cwpapi import cwp_api
cwp_api=cwp_api(
    api_key="YOUR_CWP_API_HERE", 
    server_ip="YOUR_CWP_SERVER_IP_HERE"
)

accounts=cwp_api.get_accounts()
for accounts in accounts:
    print(account.username, account.domain)

```
