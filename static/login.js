/*
Lifted from
https://github.com/lodash/lodash/blob/86a852fe763935bb64c12589df5391fd7d3bb14d/memoize.js

to avoid including the whole lodash lib.
*/
function memoize(func, resolver) {
  if (typeof func !== 'function' || (resolver != null && typeof resolver !== 'function')) {
    throw new TypeError('Expected a function')
  }
  const memoized = function(...args) {
    const key = resolver ? resolver.apply(this, args) : args[0]
    const cache = memoized.cache

    if (cache.has(key)) {
      return cache.get(key)
    }
    const result = func.apply(this, args)
    memoized.cache = cache.set(key, result) || cache
    return result
  }
  memoized.cache = new (memoize.Cache || Map)
  return memoized
}

memoize.Cache = Map

// We are XDMoD (kind of)
xdmodUrl = ''
origXdmod = 'https://xdmod.example.org'

/**
* These functons are taken from core ood code to perform login.
* Source:
* https://github.com/OSC/ondemand/blob/8f1bfb3e9de2f32e54be18876a2a985c49cef061/apps/dashboard/app/assets/javascripts/application.js
*
*/


function promiseLoginToXDMoD(xdmodUrl){
  return new Promise(function(resolve, reject){

    var promise_to_receive_message_from_iframe = new Promise(function(resolve, reject){
      window.addEventListener("message", function(event){
        if (event.origin !== xdmodUrl){
          console.log('Received message from untrusted origin, discarding');
          return;
        }
        else if(event.data.application == 'xdmod'){
          if(event.data.action == 'loginComplete'){
            resolve();
          }
            else if(event.data.action == 'error'){
              console.log('ERROR: ' + event.data.info);
              let iframe = document.querySelector("#xdmod_login_iframe");
              reject(new Error(`XDMoD Login iFrame at URL ${iframe && iframe.src} posted error message with info ${event.data.info}`));
          }
        }
      }, false);
    });

    fetch(xdmodUrl + 'rest/auth/idpredirect?returnTo="gui%2Fgeneral%2Flogin.php"')
      .then(response => response.ok ? Promise.resolve(response) : Promise.reject())
      .then(response => response.json())
      .then(function(data){
        data = data.replace(origXdmod, '');
        return new Promise(function(resolve, reject){
          var xdmodLogin = document.createElement('iframe');
          xdmodLogin.style = 'visibility: hidden; position: absolute;left: -1000px';
          xdmodLogin.id = 'xdmod_login_iframe'
          xdmodLogin.src = data;
          document.body.appendChild(xdmodLogin);
          xdmodLogin.onload = function(){
            resolve();
          }
          xdmodLogin.onerror = function(){
            reject(new Error('Login failed: Failed to load XDMoD login page'));
          }
        });
      })
      .then(() => {
        return Promise.race([promise_to_receive_message_from_iframe, new Promise(function(resolve, reject){
          setTimeout(reject, 5000, new Error('Login failed: Timeout waiting for login to complete'));
        })]);
      })
      .then(() => {
        resolve();
      })
      .catch((e)=> {
        reject(e);
      });
  });
}

var promiseLoggedIntoXDMoD = (function(){
  return memoize(function(xdmodUrl){
    return fetch(xdmodUrl + 'rest/v1/users/current', { credentials: 'include' })
      .then((response) => {
        if(response.ok){
          return Promise.resolve(response.json());
        }
        else{
          return promiseLoginToXDMoD(xdmodUrl)
                .then(() => fetch('rest/v1/users/current', { credentials: 'include' }))
                .then(response => response.json());
        }
      })
      .then((user_data) => {
        if(user_data && user_data.success && user_data.results && user_data.results.person_id){
          return Promise.resolve(user_data);
        }
        else{
          return Promise.reject(new Error('Attempting to fetch current user info from Open XDMoD failed'));
        }
      });
  });
})();

// Login immediatly
promiseLoggedIntoXDMoD(xdmodUrl);
