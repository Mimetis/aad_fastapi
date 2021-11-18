import json
import os
import pathlib
from os import environ

import msal
import requests
from aad import AadClient, AuthError, AuthToken, ensure_user_from_token
from dotenv import load_dotenv
from flask import Flask, redirect, render_template, request, session, url_for
from flask_session import Session  # https://pythonhosted.org/Flask-Session
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# This section is needed for url_for("foo", _external=True) to automatically
# generate http scheme when this sample is running on localhost,
# and to generate https scheme when it is deployed behind reversed proxy. See also
# https://flask.palletsprojects.com/en/1.0.x/deploying/wsgi-standalone/#proxy-setups
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

client_id = os.environ["CLIENT_ID"]
domain = os.environ["DOMAIN"]

dir = pathlib.Path(__file__).parent.parent.absolute()
localenv = os.path.join(dir, "local.env")
if os.path.exists(localenv):
    load_dotenv(localenv, override=True)

client_id = os.environ["CLIENT_ID"]
domain = os.environ["DOMAIN"]
api_url = environ.get("API_URL")


@app.route("/", methods=["GET", "POST"])
async def index():
    try:

        aad_client = AadClient(session=session)

        redirect_url = url_for("authorized", _external=True)

        flow = await aad_client.build_auth_code_flow(
            aad_client.options.scopes, redirect_url
        )

        if request.method == "POST":
            token = request.form["txt_access_token"]
            auth_token = AuthToken(token)
            if token is not None and token != "":
                user = ensure_user_from_token(auth_token, False)
                session["access_token"] = token
                session["claims"] = user.claims
                session["user"] = user.username
            data = requests.get(f"{api_url}/engines", auth=auth_token).json()
            session["data"] = data
        else:
            session["data"] = None

        user = await aad_client.get_user()

        username = user.name if user is not None else ""
        claims = json.dumps(user.claims) if user is not None else None
        message = session.get("message", "")
        access_token = session.get("access_token", "")
        data = json.dumps(session["data"]) if "data" in session else ""

        return render_template(
            "index.html",
            username=username,
            auth_url=flow["auth_uri"],
            version=msal.__version__,
            claims=claims,
            message=message,
            access_token=access_token,
            data=data,
        )

    except AuthError as aex:
        return render_template(
            "auth_error.html",
            result={"error": aex.code, "error_description": aex.description},
        )
    except Exception as ex:
        return render_template(
            "auth_error.html",
            result={"error": "Unknwon error", "error_description": ex.args[0]},
        )


@app.route("/userlogin")
async def userlogin():
    aad_client = AadClient(session=session)
    redirect_url = url_for("authorized", _external=True)

    flow = await aad_client.build_auth_code_flow(
        aad_client.options.scopes, redirect_url
    )

    auth_url = flow["auth_uri"]
    return redirect(auth_url)


@app.route(
    "/auth/oauth2-redirect"
)  # Its absolute URL must match your app's redirect_uri set in AAD
async def authorized():
    try:
        aad_client = AadClient(session=session)
        user = await aad_client._acquire_token_and_user_by_auth_code_flow(
            aad_client.options.scopes, request.args
        )

        session["access_token"] = user.auth_token.access_token

    except AuthError as ae:
        print(ae)
        return render_template(
            "auth_error.html",
            result={"error": ae.code, "error_description": ae.description},
        )
    except ValueError as ve:  # Usually caused by CSRF
        print(ve)
        pass  # Simply ignore them
    except Exception as ex:
        print(ex)
        return render_template(
            "auth_error.html",
            result={"error": "Unknown", "error_description": ex.args[0]},
        )

    return redirect(url_for("index"))


@app.route("/logout")
def logout():
    session.clear()  # Wipe out user and its token cache from session
    aad_client = AadClient(session=session)
    return redirect(
        aad_client.get_logout_uri(url_for("index", _external=True))
    )  # Also logout from your tenant's web session


@app.route("/apicall")
async def apicall():

    try:
        aad_client = AadClient(session=session)
        token = await aad_client.acquire_user_token()

    except AuthError:
        return redirect(url_for("login"))

    graph_data = requests.get(
        f"{api_url}/user_from_graph?criteria=heidi", auth=token
    ).json()
    return render_template("display.html", result=graph_data)


@app.route("/graph/me")
def api_call_graph_me():

    try:
        authToken = AuthToken(session["access_token"])

        graph_data = requests.get(f"{api_url}/users/me", auth=authToken).json()

    except AuthError:
        return redirect(url_for("login"))

    return render_template("display.html", result=graph_data)


@app.route("/graph/search")
async def api_call_graph_search():

    try:

        authToken = AuthToken(session["access_token"])
        user = ensure_user_from_token(auth_token=authToken, validate=False)

        aad_client = AadClient()

        # Get a new token on behalf of the user, with new scopes
        authorized_graph_user = await aad_client.acquire_user_token(user, "User.Read")

        params = {
            "$count": "true",
            "$top": "50",
            "$orderBy": "displayName",
            "$search": '"mail:spertus@microsoft.com"',
        }

        headers = {"ConsistencyLevel": "eventual"}

        graph_data = requests.get(
            "https://graph.microsoft.com/beta/users",
            headers=headers,
            params=params,
            auth=authorized_graph_user.auth_token,
        ).json()

    except AuthError:
        return redirect(url_for("login"))

    return render_template("display.html", result=graph_data)


if __name__ == "__main__":
    app.run()
