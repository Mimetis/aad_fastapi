# Protecting your FAST API web API with Azure AD



## Register your application within your Azure AD tenant

There are two applications to register:
- First one will protect the Web API. It will only allows bearer token to access with the correct scope.
- Second one will allow the user to authenticate himself and get a token to access the Web API, using the correct scope.

### Register the Web API application

The Web API application does not need to allow user to authenticate. The main purpose of this application is to protect our Web API.

1. Navigate to the Microsoft identity platform for developers [App registrations](https://go.microsoft.com/fwlink/?linkid=2083908) page.
1. Select **New registration**.
1. In the **Register an application page** that appears, enter your application's registration information:
   - In the **Name** section, enter an application name, for example `py-api`.
   - Under **Supported account types**, select **Accounts in this organizational directory only (Microsoft only - Single tenant)**.
   - Select **Register** to create the application.
1. In the app's registration screen, find and note the **Application (client) ID**. You use this value in your app's configuration file(s) later in your code.
1. Select **Save** to save your changes.										
1. In the app's registration screen, select the **Expose an API** blade to the left to open the page where you can declare the parameters to expose this app as an API for which client applications can obtain [access tokens](https://docs.microsoft.com/azure/active-directory/develop/access-tokens) for.
The first thing that we need to do is to declare the unique [resource](https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-auth-code-flow) URI that the clients will be using to obtain access tokens for this API. To declare an resource URI, follow the following steps:
   - Click `Set` next to the **Application ID URI** to generate a URI that is unique for this app.
   - For this sample, we are using the domain name and the client id as theApplication ID URI (https://{domain}.onmicrosoft.com/{clientId}) by selecting **Save**.
1. All APIs have to publish a minimum of one [scope](https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-auth-code-flow#request-an-authorization-code) for the client's to obtain an access token successfully. To publish a scope, follow the following steps:
   - Select **Add a scope** button open the **Add a scope** screen and Enter the values as indicated below:
        - For **Scope name**, use `user_impersonation`.
        - Select **Admins and users** options for **Who can consent?**
        - Keep **State** as **Enabled**
        - Click on the **Add scope** button on the bottom to save this scope.																																					
### Register the Client application 

The Client application will allow the user to authenticate, and will expose a scope to the Web Api application.

1. Navigate to the Microsoft identity platform for developers [App registrations](https://go.microsoft.com/fwlink/?linkid=2083908) page.
1. Select **New registration**.
1. In the **Register an application page** that appears, enter your application's registration information:
   - In the **Name** section, enter an application name that will be displayed to users, for example `py-web`.
   - Under **Supported account types**, select **Accounts in this organizational directory only (Microsoft only - Single tenant)**.
1. Select **Register** to create the application.
1. In the app's registration screen, find and note the **Application (client) ID**. You use this value in your app's configuration file(s) later in your code.
1. In the app's registration screen, select **Authentication** in the menu.
   - If you don't have a platform added, select **Add a platform** and select the **Web** option.
   - In the **Redirect URIs** | **Suggested Redirect URIs for public clients (mobile, desktop)** section, select **http://localhost:5000/auth/oauth2-redirect**
   - Select again **Add a platform** and select the **Single-page application** option.
   - In the **Redirect URIs** | **Suggested Redirect URIs for public clients (mobile, desktop)** section, select **http://localhost:5000/docs/oauth2-redirect**
1. Select **Save** to save your changes.

Do not activate the implicit flow, as we are using the **new Authorization Code Flow with PKCE** (https://oauth.net/2/pkce/)

1. In the app's registration screen, click on the **Certificates & secrets** blade in the left to open the page where we can generate secrets and upload certificates.
1. In the **Client secrets** section, click on **New client secret**:
   - Type a key description (for instance `sample` in our sample),
   - Select one of the available key durations (**In 1 year**, **In 2 years**, or **Never Expires**) as per your security concerns.
   - The generated key value will be displayed when you click the **Add** button. Copy the generated value for use in the steps later.
   - You'll need this key later in your code's configuration files. This key value will not be displayed again, and is not retrievable by any other means, so make sure to note 

1. In the app's registration screen, click on the **API permissions** blade in the left to open the page where we add access to the APIs that your application needs.
   - Click the **Add a permission** button and then,
   - Ensure that the **My APIs** tab is selected.
   - In the list of APIs, select the API `py-api`.
   - In the **Delegated permissions** section, select the **user_impersonation** in the list.
   - Click on the **Add permissions** button at the bottom.

### Configure Known Client Applications in the Web API application

For a middle tier Web API to be able to call a downstream Web API, the middle tier app needs to be granted the required permissions as well.
However, since the middle tier cannot interact with the signed-in user, it needs to be explicitly bound to the client app in its Azure AD registration.
This binding merges the permissions required by both the client and the middle tier Web API and presents it to the end user in a single consent dialog. The user then consent to this combined set of permissions.

To achieve this, you need to add the **Application Id** of the client app (`py-web` in our sample), in the Manifest of the Web API in the `knownClientApplications` property. Here's how:

1. In the [Azure portal](https://portal.azure.com), navigate to your `py-api` app registration, and select **Expose an API** section.
1. In the textbox, fill the Client ID of the `py-web` application
1. Select the authorized scope `user_impersonation`
1. Click **Add application**

## Configure the .devcontainer

Open the project in VS Code and configure correctly the **.devcontainer/devcontainer.json** file:

``` ini
TENANT_ID={GUID} # The tenant id where you've created the application registrations
SUBSCRIPTION_ID= {GUID} # Your subscription id
DOMAIN={domain}.onmicrosoft.com # the domain name
AUTHORITY=https://login.microsoftonline.com/{tenant_id} # Authority used to login in Azure AD

# App Registration information for Web Authentication
CLIENT_ID={GUID} # This client id is the authentication client id used by the user (from `py-web` application registration)
CLIENT_SECRET= {PWD} # you 
SCOPES=https://{domain}.onmicrosoft.com/{client_id}/user_impersonation : # Scope exposed to the `py-web` application
API_URL=http://localhost:8000
VAULT_NAME={Vault Name} # Optional : Key vault used to store the secret
VAULT_SECRET_KEY={Vault key} # Optional : Key vault secret's key

# App Registration information for Api Protection
API_CLIENT_ID={GUID} # Client id for the web api protection (from `py-api` application registration)

```

## Run the application

The solutions provides a `launch.json` example (in the **/.vscode** folder) that you can use to launch the demo.

1. In VS Code, select the Run and Debug blade on the left pane
1. Select the **API** sub menu item and click the green arrow (or hit **F5**)
1. Navigate to the url http://localhost:8000/docs and test the user authentication experience

> You don't need to fill the secret textbox when trying to authenticate your user, since we are using the PKCE method
