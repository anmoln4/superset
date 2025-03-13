from flask_appbuilder.security.views import expose
from superset.security import SupersetSecurityManager
from flask_appbuilder.security.manager import BaseSecurityManager
from flask_appbuilder.security.manager import AUTH_REMOTE_USER
from flask import  redirect, request, flash, g
from flask_login import login_user
import traceback
#import base64
import jwt
import json
#from base64 import b64decode
from flask_appbuilder.security.forms import LoginForm_db
from flask_appbuilder.security.views import UserDBModelView,AuthDBView
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from datetime import datetime
import os

# importing ast module
import ast

# Create a custom view to authenticate the user
AuthRemoteUserView=BaseSecurityManager.authremoteuserview
class CustomAuthUserView(AuthRemoteUserView):
    login_template="appbuilder/general/security/login_db.html"
    @expose('/login/', methods=['GET', 'POST'])
    def login(self):
        #token = request.args.get('token')
        next = request.args.get('next')
        referrer = request.headers.get("Referer");
        print("referer------>",referrer);
        header_url=os.getenv('APP_NAME','dryice-aws.com')
        print("header_url---",header_url)
        if (referrer is None):
            print("not embeded url-----------------")
            referrer="login"
        print("referrer if it is none-----------------------------------",referrer)
        ApplicationCheck=False
        if (referrer !="None" and referrer != ""):
            print("referrer is not none------------")
            ApplicationCheck="localhost:3000" in referrer or header_url in referrer or "localhost:8080" in referrer or "xsmdev.dryice-aws.com" in referrer
            print("Application value --->",ApplicationCheck)
        print("next-->",next)
        form=LoginForm_db()
        sm = self.appbuilder.sm
        session = sm.get_session
        user = session.query(sm.user_model).filter_by(username='IntegrationUser@hcl.com').first()
        try:
            print("Inside try-------------")
            if (ApplicationCheck):
                login_user(user, remember=False,force=True)
                if (next is not None):
                    print("inside 1st if --------")
                    return redirect(next)
                else:
                    print("inside 2nd vlock-----------")
                    return redirect(self.appbuilder.get_url_for_index)
            else:
                print("else block for direct hit")
                if form.validate_on_submit():
                   user = self.appbuilder.sm.auth_user_db(
                   form.username.data, form.password.data)
                   login_user(user, remember=False)
                   return redirect(self.appbuilder.get_url_for_index)
                return self.render_template(self.login_template,title=self.title,form=form,appbuilder=self.appbuilder)

        except:
            print("error while decode the token")
            traceback.print_exc()
            if form.validate_on_submit():
               user = self.appbuilder.sm.auth_user_db(
               form.username.data, form.password.data)
               login_user(user, remember=False)
               return redirect(self.appbuilder.get_url_for_index)
            return self.render_template(self.login_template,title=self.title,form=form,appbuilder=self.appbuilder)

# Create a custom Security manager that overrides the CustomAuthUserView
class CustomSecurityManager(SupersetSecurityManager):
    authremoteuserview = CustomAuthUserView
    def __init__(self,appbuilder):
        super(CustomSecurityManager,self).__init__(appbuilder)
