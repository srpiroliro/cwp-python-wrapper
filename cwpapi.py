import base64,requests, random, string

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


# EXCEPTIONS #

class CWPException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class CWPAccountNotFoundException(CWPException):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)
class CWPNoUsernamesAvailableException(CWPException):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

# END EXCEPTIONS #



class CWPAccount:
    def __init__(self, account_data:dict):

        self.package_name:str=account_data["package_name"]
        self.package_id=account_data["idpackage"]

        self.id:int=account_data["id"]
        self.username:str=account_data["username"]
        self.domain:str=account_data["domain"]

        self.backup=account_data["backup"]
        self.email:str=account_data["email"]
        self.setup_date=account_data["setup_date"]
        self.ip_address:str=account_data["ip"]
        self.reseller_id=account_data["reseller"]
        self.owner:str=account_data["owner"]
        self.disk_usage:int=account_data["diskused"]
        self.disk_limit:int=account_data["disklimit"]
        self.bandwidth=account_data["bandwidth"]
        self.bandwidth_limit=account_data["bwlimit"]
        self.status=account_data["status"]
    
    def __str__(self) -> str:
        return f"CWPAccount(username={self.username}, domain={self.domain}, package={self.package_name}, status={self.status})"
    

class CWPapi:
    ACCOUNT_URL="account/"
    ACCOUNT_DETAILS_URL="accountdetails/"
    ACCOUNT_PACK_CHANGE_URL="changepack/"
    ACCOUNT_QUOTA_URL="quota/"
    AUTOSSL_URL="autossl/"
    AUTOLOGIN_URL="user_session/"
    CHANGE_PASSWORD_URL="changepass/"
    CRONJOBS_URL="cronjobsusers/"
    CLUSTER_CWP_URL="cluster/"
    DOMAINS_ADMIN_URL="admindpmains/"
    DNS_CLLUSTER_URL="dns_cluster/"
    DKIM_URL="dkim/"
    EMAIL_URL="email/"
    ADMIN_EMAIL_URL="emailadmin/"
    FTP_URL="ftp/"
    ACCOUNT_METADATA_URL="account_metadata/"
    MYSQL_DBS_URL="databasemysql/"
    MYSQL_USERS_URL="usermysql/"
    PACKAGES_URL="packages/"
    QUOTA_LIMIT_URL="quotalimit/"
    TYPE_SERVER_URL="typeserver/"

    POSSIBLE_ACTIONS = ["add", "udp", "del", "list", "susp", "unsp"]

    DEFAULT_REQUEST_DATA = {
        "key": "",
        "action": ""
    }

    MAX_USERNAME_LENGTH = 8

    def __init__(self, 
        api_key:str, 
        server_ip:str, 
        server_api_port:int=2304, 
        server_https:bool=True, 
        api_version:str="v1", 
        default_cwp_email:str="", 
        username_identifier:str="w"
    ):
        """
            api_key: API key for CWP
            server_ip: IP address of CWP server
            server_api_port: Port of CWP API. Default: 2304
            server_https: Use HTTPS for CWP API. Default: True
            api_version: API version. Default: v1
            default_cwp_email: Default email for CWP. Default: ""
        """
        self.api_key = api_key
        self.api_root = "http"+("s" if server_https else "")+"://"+server_ip+":"+str(server_api_port)+"/"+api_version+"/"
        self.api_version = api_version

        self.server_ip = server_ip

        self.DEFAULT_REQUEST_DATA["key"] = self.api_key

        self.default_cwp_email = default_cwp_email

        self.username_identifier = username_identifier

    
    def get_domain_account(self, domain:str)->CWPAccount:
        """
            Get account details from domain
        """
        all_accounts=self._post(self.ACCOUNT_DETAILS_URL, "list")
        for raw_account in all_accounts:
            if raw_account["domain"] == domain:
                return CWPAccount(raw_account)
        
        raise CWPAccountNotFoundException(f"Account with domain {domain} not found")

    def get_accounts(self)->list[CWPAccount]:
        """
            List all accounts
        """
        raw_accounts=self._post(self.ACCOUNT_URL, "list")
        return [CWPAccount(account_data) for account_data in raw_accounts]
    
    def add_account(self,
        domain:str, 
        email:str|None=None, 
        package:str="default",
        inode:int|None=None,
        limit_nproc:int|None=None,
        limit_nofile:int|None=None,
        server_ips:str|None="default",
        autossl:bool=True,
        encodepass:bool=True,
        reseller:int|None=None, 
        lang:str|None=None,
        debug:bool=False,
        username:str|None=None, 
        password:str|None=None
    )->None:
        """
            Add account.
            domain:str 	->  main domain associated with the account
            user:str|None 	->  username to create. By default it generates an incremental username "wXXX"
            pass:str|None ->  	Password for the account. By default its randomly generated.
            email:str|None  -> 	Email Address of the account owner. By default it uses the default email address specified in the constructor. If none was specified, None will be used.
            package:str  ->	Create account with package. By default it uses the "default" package.
            inode: 	->     ?? Not specified in documentation ??
            limit_nproc:  ->    ?? Not specified in documentation ??
            limit_nofile: 	->   ?? Not specified in documentation ??
            server_ips: 	->  ?? Not specified in documentation ??. Defaults to server IP.
            autossl:bool 	-> 	(true/false) Enable AutoSSL for the account. By default it is enabled.
            encodepass:bool  ->	(true/false if the option is true, you must send the password base64 encoded). By default it is enabled.
            reseller:int|None   -> 	(1 = To resell, Account Reseller for a Reseller's Package, Empty for Standard Package)
            lang:str|None   -> 	Indicate the language in which you want the user panel (optional)
            debug:bool  -> 	(0 / 1) Debug display file: /var/log/cwp/cwp_api.log (optional)
        """

        if not username:
            username = self._get_new_username()

        if not password:
            password = self._gen_password()
        
        if encodepass:
            password = base64.b64encode(password.encode("utf-8")).decode("utf-8")

        if email: 
            email = self.default_cwp_email
        
        if server_ips == "default":
            server_ips = self.server_ip


        self._post(self.ACCOUNT_URL, "add", {
            "domain": domain,
            "user": username,
            "pass": password,
            "email": email,
            "package": package,
            "inode": inode,
            "limit_nproc": limit_nproc,
            "limit_nofile": limit_nofile,
            "server_ips": server_ips,
            "autossl": autossl,
            "encodepass": encodepass
        })


    # TODO: ALL the other functions ...


    def _get_new_username(self)->str:
        """
            Create new username witha lenght of 8chars. A format of username_identifier+number. Example: w0000001
        """
        all_accounts=self.get_accounts()

        usernames=[]
        for account in all_accounts:
            username_number=account.username.strip(self.username_identifier)
            if username_number.isdigit(): usernames.append(int(username_number))
        usernames.sort()
        
        last=usernames[0]
        for current in usernames[1:]:
            if current-last>1: break
            last=current
        
        numbers=self.MAX_USERNAME_LENGTH-len(self.username_identifier)
        future_username=last+1
        result=str(pow(10,numbers)+future_username)[1:]

        if pow(10,numbers)<future_username:
            raise CWPNoUsernamesAvailableException("No more usernames available")

        return f"{self.username_identifier}{result}" 

    def _post(self, top_url:str, action:str, data:dict={}):
        """
            top_url: Top URL of API
            action: Action to perform
            data: Data to send
        """

        post_data = self.DEFAULT_REQUEST_DATA.copy()
        post_data["action"] = action
        if data: post_data.update(data)

        response=requests.post(self.api_root+top_url, data=post_data, verify=False)
        if not response:
            raise CWPException(f"No response from CWP API. response.text={response.text}")

        response_json=response.json()
        if response_json["status"].lower() == "error":
            raise CWPException(response_json["msj"])
        
        return response_json["msj"]

    def _gen_password(self, length:int=20)->str:
        """
            Generate random password
        """
        return "".join(random.choice(string.ascii_letters+string.digits) for _ in range(length))