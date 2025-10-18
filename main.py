from bs4 import BeautifulSoup
import json
import os
import re
import requests
import subprocess
import time

# Setup debug mode if applicable
DEBUG = os.getenv("DEBUG") == "1"

### Helper functions ###


# Make a call to openconnect
def openconnect(*args: str) -> subprocess.CompletedProcess:
    args = ("openconnect", *list(args))
    p = subprocess.run(args, capture_output=True)
    return p


# Make a full vpn connection using openconnect
def connect(username: str, prelogin_cookie: str) -> subprocess.CompletedProcess:
    print("Staring openconnect connection...")
    p = subprocess.run(
        [
            "openconnect",
            "--protocol=gp",
            "--usergroup=gateway:prelogin-cookie",
            "-u",
            username,
            "--passwd-on-stdin",
            get_gateway(),
        ],
        input=prelogin_cookie + "\n",
        text=True,
    )
    print("Openconnect process completed.")
    return p


# Much of the needed info is stored in a javscript variable called $Config
# This finds the appropriate line in a response string and parses to dict
def parse_js_config(content: str) -> dict[str, str]:
    search = re.search("Config=(.*);", content)
    if search is not None:
        config_raw = search.group(1)
    else:
        print("Unable to parse config")
        exit()
    return json.loads(config_raw)


### Login flow


# Use openconnect to hit globalprotect to get a sign in url
def get_login_url() -> str:

    p = openconnect("--protocol=gp", get_gateway())

    stdout = p.stdout.decode()

    if "Failed to connect to" in stdout:
        print(f"Failed to connect to {get_gateway()}.")
        exit()

    try:
        url = p.stdout.decode().split("\n")[-2][45:]
    except IndexError as _:
        print("Could not retrieve login url")
        exit()

    return url


# Hit the sign in url to get initial session data
def inital_login() -> dict[str, str]:
    # Hit the inital login url
    url = get_login_url()
    resp = requests.get(url)

    config = parse_js_config(resp.content.decode())

    # Extact relevant data
    return {
        "request_id": config["sessionId"],
        "canary": config["canary"],
        "ctx": config["sCtx"],
        "flow_token": config["sFT"],
    }


# Use session data to do a password login, returning resulting config
def password_login(
    username: str,
    password: str,
    request_id: str,
    canary: str,
    ctx: str,
    flow_token: str,
) -> dict[str, str]:

    const_data = {
        "i13": "0",
        "type": "11",
        "LoginOptions": "3",
        "lrt": "true",
        "lrtPartition": "prod1",
        "hisRegion": "asia1",
        "hisScaleUnit": "1",
        "ps": "2",
        "psRNGCDefaultType": "",
        "psRNGCEntropy": "",
        "psRNGCSLK": "",
        "PPSX": "",
        "NewUser": "1",
        "FoundMSAs": "",
        "fspost": "0",
        "i21": "0",
        "CookieDisclosure": "0",
        "IsFidoSupported": "1",
        "isSignupPost": "0",
        "DfpArtifact": "",
        "i19": "19814",
    }

    data = const_data | {
        "canary": canary,
        "ctx": ctx,
        "hpgrequestid": request_id,
        "flowToken": flow_token,
        "login": username,
        "loginfmt": username,
        "passwd": password,
    }

    resp = requests.post(
        "https://login.microsoftonline.com/e37d725c-ab5c-4624-9ae5-f0533e486437/login",
        data=data,
    )

    config = parse_js_config(resp.content.decode())

    # Test if auth is proceeding to MFA
    if "arrUserProofs" not in config:
        print("Not prompted for MFA, probably incorrect password")
        exit()

    return {
        "ctx": config["sCtx"],
        "flow_token": config["sFT"],
        "canary": config["canary"],
    }


# MFA Step 1, start session
def otp_begin_auth(ctx: str, flow_token: str) -> dict[str, str]:
    data = {
        "AuthMethodId": "PhoneAppOTP",
        "Method": "BeginAuth",
        "ctx": ctx,
        "flowToken": flow_token,
    }

    resp = requests.post(
        "https://login.microsoftonline.com/common/SAS/BeginAuth",
        data=json.dumps(data),
    )

    result = resp.json()

    if not result["Success"]:
        print("MFA initialisation failed.")
        exit()

    return {"ctx": result["Ctx"], "flow_token": result["FlowToken"]}


# MFA step 2, actually submit token
def otp_end_auth(
    session_id: str,
    ctx: str,
    flow_token: str,
    otp: str,
) -> dict[str, str]:
    data = {
        "Method": "EndAuth",
        "SessionId": session_id,
        "FlowToken": flow_token,
        "Ctx": ctx,
        "AuthMethodId": "PhoneAppOTP",
        "AdditionalAuthData": otp,
        "PollCount": 1,
    }

    resp = requests.post(
        "https://login.microsoftonline.com/common/SAS/EndAuth", data=json.dumps(data)
    )

    result = resp.json()

    if not result["Success"]:
        print("MFA authentication failed.")
        exit()

    return {"ctx": result["Ctx"], "flow_token": result["FlowToken"]}


# MFA step 3, submit everything
def otp_process_auth(
    username: str,
    otp: str,
    request_id: str,
    ctx: str,
    flow_token: str,
    canary: str,
) -> dict[str, str]:
    const_data = {
        "type": "19",
        "GeneralVerify": "false",
        "mfaAuthMethod": "PhoneAppOTP",
        "rememberMFA": "true",
        "sacxt": "",
        "hideSmsInMfaProofs": "false",
        "i19": "14875",
    }

    curr_time = int(time.time_ns() / (10**6))
    mfa_start = curr_time
    mfa_end = curr_time + 110

    data = const_data | {
        "login": username,
        "otc": otp,
        "mfaLastPollStart": str(mfa_start),
        "mfaLastPollEnd": str(mfa_end),
        "hpgrequestid": request_id,
        "request": ctx,
        "flowToken": flow_token,
        "canary": canary,
    }

    resp = requests.post(
        "https://login.microsoftonline.com/common/SAS/ProcessAuth",
        data=data,
    )

    soup = BeautifulSoup(resp.content, "html.parser")

    result = {}

    # Grab target url
    url = soup.find_all("form")[0].get("action")
    result["url"] = url

    # Grab form input fields
    for input in soup.find_all("input"):
        if input.get("type") != "submit":
            name = input.get("name")
            value = input.get("value")
            result[name] = value

    # Grab javascript nonce
    nonce = soup.find_all("script")[0].get("nonce")
    result["nonce"] = nonce

    return result


# Submit saml token to get global protect login cookie
def submit_saml(
    url: str,
    saml_token: str,
    relay_state: str,
) -> dict[str, str]:
    data = {
        "SAMLResponse": saml_token,
        "RelayState": relay_state,
    }

    resp = requests.post(url, data=data)

    # Parse required attributes
    def find(content: str, target: str):
        search = re.search(f"<{target}>(.*)</{target}>", content)
        if search is not None:
            return search.group(1)
        else:
            print("Unable to parse SAML result")
            exit()

    body = resp.content.decode()
    return {
        "prelogin_cookie": find(body, "prelogin-cookie"),
        "saml_username": find(body, "saml-username"),
    }


# Perform a full login flow, returning a username and prelogin cookie
def full_login() -> dict[str, str]:
    session_data = inital_login()

    password_login_data = password_login(
        username=get_username(),
        password=get_password(),
        **session_data,
    )

    # Use the same token for the whole flow
    otp = get_otp()

    if DEBUG:
        print("Starting MS auth")

    otp_begin_data = otp_begin_auth(
        password_login_data["ctx"], password_login_data["flow_token"]
    )
    if DEBUG:
        print("Starting MS auth end")
    otp_end_data = otp_end_auth(
        session_id=session_data["request_id"],
        ctx=otp_begin_data["ctx"],
        flow_token=otp_begin_data["flow_token"],
        otp=otp,
    )
    if DEBUG:
        print("Starting MS auth process")
    otp_process_data = otp_process_auth(
        username=get_username(),
        otp=otp,
        request_id=session_data["request_id"],
        ctx=otp_end_data["ctx"],
        flow_token=otp_end_data["flow_token"],
        canary=password_login_data["canary"],
    )
    if DEBUG:
        print("MS auth finished")

    # Submit saml to globalprotect
    gp_credentials = submit_saml(
        otp_process_data["url"],
        otp_process_data["SAMLResponse"],
        otp_process_data["RelayState"],
    )

    if DEBUG:
        print(f"GP Credentials: {gp_credentials}")

    return {
        "username": gp_credentials["saml_username"],
        "prelogin_cookie": gp_credentials["prelogin_cookie"],
    }


### Credential management

# Global variables to only prompt user once
gateway = None
username = None
password = None
otp_secret = None


# Gateway getter
def get_gateway() -> str:
    global gateway
    if gateway is not None:
        return gateway
    elif gateway := os.getenv("GATEWAY"):
        return gateway
    else:
        gateway = input("Gateway: ")
        return gateway


# User getter
def get_username() -> str:
    global username
    if username is not None:
        return username
    elif username := os.getenv("EMAIL"):
        return username
    else:
        username = input("Email: ")
        return username


# Password getter
def get_password() -> str:
    global password
    if password is not None:
        return password
    elif password := os.getenv("PASSWORD"):
        return password
    else:
        password = input("Password: ")
        return password


# OTP getter, which tries to get a totp secret from env,
# falling back to promping user
def get_otp() -> str:
    def gen_otp(secret: str):
        import pyotp

        totp = pyotp.TOTP(secret)
        code = totp.now()

        return code

    global otp_secret

    if otp_secret is not None:
        return gen_otp(otp_secret)
    elif otp_secret := os.getenv("OTP_SECRET"):
        return gen_otp(otp_secret)
    else:
        return input("OTP: ")


def main() -> None:
    header = (
        "#############################################\n"
        "### Starting python managed GlobalProtect ###\n"
        "#############################################\n"
    )
    print(header)

    while True:
        print("Retrieving login details...")
        credentials = full_login()
        print(f"Connecting to {get_gateway()} as {credentials['username']}")
        connect(**credentials)


if __name__ == "__main__":
    main()
