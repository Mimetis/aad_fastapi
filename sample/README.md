# AD Sample

## Application registration

Before running the sample application, be sure to have an **Application Registration** available to authenticate yourself within the web app.  

You can refer to the [Authentication guide](../../docs/user-guide/authentication.md) to validate you have an application registration available.

Also check that you have two redirections registered in your **Application Registration**:
- `https://localhost:5000/oauth2-redirect`
- `https://localhost:8000/docs/oauth2-redirect`

## Before launching the sample

Be sure to be log in azure, using the **Azure CLI**, inside the workspace container:

``` bash
az login
```

This will allow the application to replace the **Managed Identity** usage with your personal **Azure Ad Identity**

Be sure that your account has the access policies set int the **Azure Key Vault** to be able to retrieve the certificate:

![Access Policies](access-policies.png)

## local.env

Create a [local.env](local.env) file that will contains the environment variables needed to authenticate your user to the application registration.

You can use [local.env.sample](local.env.sample) as template file.

Be sure to fill all the mandatories values, extract from the **Application Registration**:

``` bash
# CLIENT_ID is the application id of your application registration
CLIENT_ID="must_be_a_guid"
# TENANT_ID is the tenant guid from your azure tenant
TENANT_ID="must_be_a_guid"
# DOMAIN can be retrieved from Azure Active Directory.
DOMAIN="bertelsmann.onmicrosoft.com"
# SCOPES must be user_impresonation as it's created automatically by the create_service_principal.sh script
SCOPES="user_impersonation"
# AUTHORITY is always https://login.microsoftonline.com/{TENANT_ID}
AUTHORITY = "https://login.microsoftonline.com/must_be_a_guid"


# VAULT_URL is the vault url containing your certificate
# Be sure that your account (for local debugging) or the Managed Identity from App Services, is allowed to read secrets/ certificates
# For local debugging, before running the application, be sure to log in azure, using your cli (az login)
VAULT_URL = "https://keyvault_name.vault.azure.net/"

# VAULT_CERTIFICATE_NAME is the certificate name contained in the vault. The certificate should exists and can be PEM or PCKS12 format
VAULT_CERTIFICATE_NAME = "certificate_name"

# API_URL is the FastAPI root uri
API_URL = "http://localhost:8000"
```

## Launching from bash

First of all, be sure to execute the commands from the `/src/aad/sample` directory.

Install the python modules required

``` bash
pip install -r requirements.txt
```

You can launch both the web api and the web ui using these commands:

``` bash
export PYTHONPATH=../src &&  python3 -m uvicorn --app-dir ./api  main:app --host localhost --port 8000 --reload
```

![API command line](api-command-line.png)

``` bash
export PYTHONPATH=../src && export FLASK_APP=./ui/app.py && python3 -m flask run --host localhost --port 5000
```

![WEB UI command line](web-command-line.png)

## Launching from Visual Studio Code

You can debug the **API** and the **WEB UI** at the same time, using a **compounds launch** system, from within **VS CODE**:

Create a `//.vscode/launch.json` file with this content:

``` json
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        {
            "name": "aad test Flask",
            "type": "python",
            "request": "launch",
            "module": "flask",
            "env": {
                "PYTHONPATH": "src/aad/sample/ui",
                "FLASK_APP": "src/aad/sample/ui/app.py",
                "FLASK_ENV": "development"
            },
            "args": [
                "run",
                "--host",
                "localhost",
                "--no-debugger"
            ],
            "jinja": true
        },
        {
            "name": "add test FastAPI",
            "type": "python",
            "request": "launch",
            "module": "uvicorn",
            "env": {
                "PYTHONPATH": "src/aad/sample/api",
                "FLASK_ENV": "development"
            },               
            "args": [
                "main:app",
                "--host",
                "localhost",
                "--port",
                "8000",
                "--reload",
            ],
            "jinja": true,
            "justMyCode": false
        }
    ],
    "compounds": [
        {
            "name": "Full",
            "configurations": [
                "aad test Flask",
                "add test FastAPI"
            ]
        }
    ]
}
```

## Exploring Web API

Once launched, you can access the **Web API docs** page using the uri: [http://localhost:8000/docs](http://localhost:8000/docs).

From this docs page, you can execute any web api, after log in, using the **Authorize** button

## Exploring Web UI

Be sure to have the Web API project launched, to be able to get responses to your requests from the Web UI to the Web API

Once launched, you can access the Web UI page using the uri [http://localhost:5000](http://localhost:5000).

From that point, you can:
- Log In.
- Call the Web API, using your personal token, and get a response.
