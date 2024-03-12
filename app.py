# Azure / EntraID research: Web App - based on MSAL examples
import logging
import jwt
import requests
from flask import Flask, current_app, render_template, redirect, url_for, request
from flask_session import Session
from pathlib import Path
import app_config
from ms_identity_web import IdentityWebPython
from ms_identity_web.adapters import FlaskContextAdapter
from ms_identity_web.errors import NotAuthenticatedError
from ms_identity_web.configuration import AADConfig


def create_app(secure_client_credential=None):
    app = Flask(__name__, root_path=Path(__file__).parent) #initialize Flask app
    app.config.from_object(app_config) # load Flask configuration file (e.g., session configs)
    Session(app) # init the serverside session for the app: this is requireddue to large cookie size
    # tell flask to render the 401 template on not-authenticated error. it is not strictly required:
    app.register_error_handler(NotAuthenticatedError, lambda err: (render_template('auth/401.html'), err.code))
    aad_configuration = AADConfig.parse_json('aad.config.json') # parse the aad configs
    app.logger.level=logging.INFO # can set to DEBUG for verbose logs

    AADConfig.sanity_check_configs(aad_configuration)
    adapter = FlaskContextAdapter(app) # ms identity web for python: instantiate the flask adapter
    ms_identity_web = IdentityWebPython(aad_configuration, adapter) # then instantiate ms identity web for python

    @app.route('/')
    @app.route('/sign_in_status')
    def index():
        return render_template('auth/status.html')

    @app.route('/token_details')
    @ms_identity_web.login_required # <-- developer only needs to hook up login-required endpoint like this
    def token_details():
        ms_identity_web.acquire_token_silently()
        access_token = ms_identity_web.id_data._access_token
        decoded_token = jwt.decode(access_token, options={"verify_signature": False, "verify_aud": False})  # Decode token
        # print("decoded token: ", decoded_token)
        current_app.logger.info("token_details: user is authenticated, will display token details")
        return render_template('auth/token.html', claims=decoded_token)

    @app.route("/call_ms_graph")
    @ms_identity_web.login_required
    def call_ms_graph():
        ms_identity_web.acquire_token_silently() 
        access_token = ms_identity_web.id_data._access_token
        decoded_token = jwt.decode(access_token, options={"verify_signature": False, "verify_aud": False})  # Decode token
        # print(decoded_token)
        graph = app.config['GRAPH_ENDPOINT_GROUPS']
        token = f'Bearer {access_token}'
        results = requests.get(graph, headers={'Authorization': token}).json()
        return render_template('auth/call-graph.html', results=results, claims=decoded_token, access_token=access_token)
    
    return app

if __name__ == '__main__':
    app=create_app() # this is for running flask's dev server for local testing purposes ONLY
    app.run(ssl_context='adhoc')

app=create_app()
