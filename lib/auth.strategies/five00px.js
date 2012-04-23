/*!
 * Copyright(c) 2010 Ciaran Jessup <ciaranj@gmail.com>
 * MIT Licensed
 */
var OAuth= require("oauth").OAuth,
    url = require("url"),
    http = require('http');

module.exports= function(options, server) {
  options= options || {}
  var that= {};
  var my= {};

  // Construct the internal OAuth client
  my._oAuth= new OAuth("https://api.500px.com/v1/oauth/request_token",
                         "https://api.500px.com/v1/oauth/access_token", 
                         options.consumerKey,  options.consumerSecret, 
                         "1.0", options.callback || null, "HMAC-SHA1");

  // Give the strategy a name
  that.name  = "five00px";
  
  // Build the authentication routes required 
  that.setupRoutes= function(app) {
    app.use('/auth/five00px_callback', function(req, res){
      req.authenticate([that.name], function(error, authenticated) {
        res.writeHead(303, { 'Location': req.session.five00px_redirect_url });
        res.end('');
      });
    });
  }

  // Declare the method that actually does the authentication
  that.authenticate= function(request, response, callback) {
    //todo: if multiple connect middlewares were doing this, it would be more efficient to do it in the stack??
    var parsedUrl= url.parse(request.originalUrl, true);
    this.trace('parsedUrl=' + request.originalUrl);
    
    //todo: makw the call timeout ....
    var self= this;
    if( request.getAuthDetails()['500px_login_attempt_failed'] === true ) {
      // Because we bounce through authentication calls across multiple requests
      // we use this to keep track of the fact we *Really* have failed to authenticate
      // so that we don't keep re-trying to authenticate forever.
      delete request.getAuthDetails()['500px_login_attempt_failed'];
      self.fail( callback );
    }
    else {
      if( parsedUrl.query && parsedUrl.query.denied ) {
        self.trace( 'User denied OAuth Access' );
        request.getAuthDetails()['500px_login_attempt_failed'] = true;
        this.fail(callback);
      }
      else if( parsedUrl.query && parsedUrl.query.oauth_token && request.session.auth["500px_oauth_token_secret"] ) {
          self.trace( 'Phase 2/2 : Requesting an OAuth access token.' );
          my._oAuth.getOAuthAccessToken(parsedUrl.query.oauth_token, request.session.auth["500px_oauth_token_secret"],
                                function( error, oauth_token, oauth_token_secret, additionalParameters ) {
                                  if( error ) {
                                    self.trace( 'Error retrieving the OAuth Access Token: ' + error );
                                    request.getAuthDetails()['500px_login_attempt_failed'] = true;
                                    this.fail(callback);
                                  }
                                  else {
                                    self.trace( 'Successfully retrieved the OAuth Access Token' );
                                    request.session.auth["500px_oauth_token_secret"]= oauth_token_secret;
                                    request.session.auth["500px_oauth_token"]= oauth_token;
                                    var user= { user_id: additionalParameters.user_id,
                                               username: additionalParameters.screen_name }
                                    self.executionResult.user= user; 
                                    self.success(user, callback)
                                  }
                                });
      }
      else {
        
        
        my._oAuth.getOAuthRequestToken(function(error, oauth_token, oauth_token_secret, oauth_authorize_url, additionalParameters ) {
          if(error) {
            self.trace( 'Error retrieving the OAuth Request Token: ' + JSON.stringify(error) );
            callback(null); // Ignore the error upstream, treat as validation failure.
          } else {
            self.trace( 'Successfully retrieved the OAuth Request Token' );
            request.session['500px_redirect_url']= request.originalUrl;
            request.session.auth["500px_oauth_token_secret"]= oauth_token_secret;
            request.session.auth["500px_oauth_token"]= oauth_token;
            self.redirect(response, "https://api.500px.com/v1/oauth/authorize?oauth_token =" + oauth_token, callback);
          }
        });
      }
    }
  }
  return that;
};
