/*
 * Copyright 2016 Red Hat Inc. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
'use strict';

const URL = require('url');

module.exports = function (keycloak) {
  return function postAuth (request, response, next) {
    if (!request.query.auth_callback) {
      return next();
    }

    //  During the check SSO process the Keycloak server answered the user is not logged in
    if (request.query.error === 'login_required') {
      return next();
    }

    if (request.query.error) {
      return keycloak.accessDenied(request, response, next);
    }

    keycloak.getGrantFromCode(request.query.code, request, response)
      .then(grant => {
        let urlParts = {
          pathname: request.path,
          query: request.query
        };

        delete urlParts.query.code;
        delete urlParts.query.auth_callback;
        delete urlParts.query.state;
        delete urlParts.query.session_state;

        let cleanUrl = URL.format(urlParts);

        request.kauth.grant = grant;
        try {
          keycloak.authenticated(request);
        } catch (err) {
          console.log(err);
        }
        let host = request.hostname;
        let headerHost = request.headers.host.split(':');
        let port = headerHost[1] || '';
        let redirectUrl = request.protocol + '://' + host + (port === '' ? '' : ':' + port);
        if(request.session.auth_redirect_uri != null || request.session.auth_redirect_uri != ''){
            cleanUrl = redirectUrl + URL.parse(request.session.auth_redirect_uri).pathname;
        }
        console.log(URL.parse(request.session.auth_redirect_uri).pathname)
        console.log(cleanUrl)
        response.redirect(cleanUrl);
      }).catch((err) => {
        keycloak.accessDenied(request, response, next);
        console.error('Could not obtain grant code: ' + err);
      });
  };
};
