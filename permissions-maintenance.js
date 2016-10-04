'use strict';
/* 
We dislike prerequisites and avoid them where possible. We especially dislike prereqs that have a 'framework' style; 
simple libraries are more palatable.
Please do not add any framework to this preqs. We do not want express or anything like it. We do not want any sort of "ORM" or similar.
Adding simple library prereqs could be OK if the value they bring is in proportion to their size and complexity 
and is warranted by the difficulty of the problem being solved.
*/
var http = require('http');
var url = require('url');
var querystring = require('querystring');
var lib = require('http-helper-functions');
var db = require('./permissions-maintenance-db.js');

var INTERNAL_SCHEME = process.env.INTERNAL_SCHEME || 'http';
var ANYONE = 'http://apigee.com/users/anyone';
var INCOGNITO = 'http://apigee.com/users/incognito';
var INTERNAL_ROUTER = process.env.INTERNAL_ROUTER;
var SHIPYARD_PRIVATE_SECRET = process.env.SHIPYARD_PRIVATE_SECRET;
if (SHIPYARD_PRIVATE_SECRET !== undefined) {
  SHIPYARD_PRIVATE_SECRET = new Buffer(SHIPYARD_PRIVATE_SECRET).toString('base64');
}

function verifyPermissions(req, permissions, user) {
  var permissionsPermissions = permissions._permissions;
  if (permissionsPermissions === undefined) {
    permissionsPermissions = permissions._permissions = {};
  }
  var rslt = lib.setStandardCreationProperties(req, permissionsPermissions, user);
  if (rslt !== null) {
    return result;
  }
  if (permissions._subject === undefined) {
    return 'invalid JSON: "_subject" property not set';
  }
  var governed = permissions._self;
  if (permissions._inheritsPermissionsOf !== undefined && !Array.isArray(permissions._inheritsPermissionsOf)) {
    return '_inheritsPermissionsOf must be an Array'
  }
  if (permissionsPermissions.update === undefined && permissions._inheritsPermissionsOf === undefined) {
    permissionsPermissions.update = [user];
    permissionsPermissions.read = permissionsPermissions.read || [user];
  }

  return null;
}

var OPERATIONS = ['create', 'read', 'update', 'delete', 'add', 'remove'];

function calculateSharedWith(req, permissions) {
  function listUsers (obj, result) {
    //console.log(Object.keys(obj).filter(x => OPERATIONS.indexOf(x) < 0))
    for (var i = 0; i < OPERATIONS.length; i++) {
      var actors = obj[OPERATIONS[i]];
      if (actors !== undefined) {
        for (var j = 0; j < actors.length; j++) {result[actors[j]] = true;}
      }
    }
  }
  var result = {};
  if (permissions._permissions) listUsers(permissions._permissions, result);
  if (permissions._self) listUsers(permissions._self, result);
  permissions._sharedWith = Object.keys(result);
}

function createPermissions(req, res, permissions) {
  var hrstart = process.hrtime();
  console.log('permissions-maintenance:createPermissions:start');
  var user = lib.getUser(req);
  if (user == null) {
    lib.unauthorized(req, res)
  } else {
    var err = verifyPermissions(req, permissions, user);
    if (err === null) {
      function primCreate(req, res, permissions) {
        calculateSharedWith(req, permissions);
        db.createPermissionsThen(req, res, permissions, function(etag) {
          addCalculatedProperties(req, permissions);
          var permissionsURL =  `//${req.headers.host}/permissions?${permissions._subject}`;
          lib.created(req, res, permissions, permissionsURL, etag);
          var hrend = process.hrtime(hrstart);
          console.log(`permissions-maintenance:createPermissions:success, time: ${hrend[0]}s ${hrend[1]/1000000}ms`);
        });        
      }
      var sharingSets = permissions._inheritsPermissionsOf;
      if (sharingSets !== undefined && sharingSets.length > 0) {
        sharingSets = sharingSets.map(x => lib.internalizeURL(x));
        var subject = lib.internalizeURL(permissions._subject);
        if (sharingSets.indexOf(subject) == -1) {
          var count = 0;
          for (var i=0; i < sharingSets.length; i++) {
            var sharingSet = sharingSets[i];
            var allowedByAll = true;
            lib.withAllowedDo(req, res, sharingSet, '_permissionsHeirs', 'add', function(allowed) {
              allowedByAll = allowedByAll && allowed;
              if (++count == sharingSets.length) {
                if (allowedByAll) {
                  primCreate(req, res, permissions);
                } else {
                  lib.forbidden(req, res);
                }
              } 
            });
          }
        } else {
          lib.badRequest(res, `cannot inherit from self: ${subject} inheritsFrom: ${sharingSets}`);
        }
      } else {
        primCreate(req, res, permissions);
      }
    } else {
      lib.badRequest(res, err);
    }
  }
}

function addCalculatedProperties(req, permissions) {
  var ancestors = permissions._inheritsPermissionsOf
  if (ancestors !== undefined) {
    permissions._permissions.inheritsPermissions = ancestors.map(x => `//${req.headers.host}/permissions?${x}`);
  }
}

function getPermissions(req, res, subject) {
  var hrstart = process.hrtime();
  console.log(`permissions-maintenance:getPermissions:start subject: ${subject}`);
  ifAllowedThen(req, res, subject, '_permissions', 'read', function(permissions, etag) {
    addCalculatedProperties(req, permissions);
    lib.found(req, res, permissions, etag);
    var hrend = process.hrtime(hrstart);
    console.log(`permissions-maintenance:getPermissions:success, time: ${hrend[0]}s ${hrend[1]/1000000}ms`);
  });
}

function deletePermissions(req, res, subject) {
  var hrstart = process.hrtime();
  console.log(`permissions-maintenance:deletePermissions:start subject: ${subject}`);
  lib.ifAllowedThen(req, res, subject, '_permissions', 'delete', function() {
    db.deletePermissionsThen(req, res, subject, function(permissions, etag) {
      addCalculatedProperties(req, permissions);
      lib.found(req, res, permissions, etag);
      var hrend = process.hrtime(hrstart);
      console.log(`permissions-maintenance:deletePermissions:success, time: ${hrend[0]}s ${hrend[1]/1000000}ms`);
    })
  })
}

function updatePermissions(req, res, subject, patch) {
  var hrstart = process.hrtime();
  console.log('permissions-maintenance:updatePermissions:start')
  ifAllowedThen(req, res, subject, '_permissions', 'update', function(permissions, etag) {
    lib.applyPatch(req, res, permissions, patch, function(patchedPermissions) {
      function primUpdatePermissions() {
        calculateSharedWith(req, patchedPermissions);
        patchedPermissions._permissions.modifier = lib.getUser(req);
        patchedPermissions._permissions.modified = new Date().toISOString();
        db.updatePermissionsThen(req, res, subject, patchedPermissions, etag, function(etag) {
          addCalculatedProperties(req, patchedPermissions); 
          lib.found(req, res, patchedPermissions, etag);
          var hrend = process.hrtime(hrstart);
          console.log(`permissions-maintenance:updatePermissions:success, time: ${hrend[0]}s ${hrend[1]/1000000}ms`);
        });    
      }
      if (req.headers['if-match'] == etag) { 
        function ifSharingSetsAllowDo(sharingSets, action, callback) {
          if (sharingSets.length > 0) {
            lib.withAllowedDo(req, res, sharingSets, '_permissionsHeirs', action, function(result) {
              if (result) {
                callback();
              } else {
                lib.forbidden(req, res);
              }
            });
          } else
            callback()
        }
        function ifAllowedToInheritFromThen(sharingSets, callback) {
          if (sharingSets === undefined || sharingSets.length == 0) {
            callback()
          } else {
            if (sharingSets.indexOf(subject) == -1) {
              var path = `/is-allowed-to-inherit-from?${sharingSets.map(x => `sharingSet=${x}`).join('&')}&subject=${subject}`
              lib.sendInternalRequest(req, res, path, 'GET', null, function(clientResponse) {
                lib.getClientResponseBody(clientResponse, function(body) {
                  if (clientResponse.statusCode == 200) { 
                    var result = JSON.parse(body);
                    if (result.result == true)
                      callback();
                    else
                      lib.badRequest(res, result.reason);
                  } else {
                    var err = `ifAllowedToInheritFromThen: unable to retrieve ${path} statusCode ${clientResponse.statusCode} text: ${body}`
                    console.log(err)
                    lib.internalError(res, err)
                  }
                })
              })
            } else 
              lib.badRequest(res, 'may not inherit permissions from self')
          }
        }
        var new_permissions = '_inheritsPermissionsOf' in patchedPermissions ? patchedPermissions._inheritsPermissionsOf : [];
        ifAllowedToInheritFromThen(new_permissions, primUpdatePermissions);
      } else {
        var err = (req.headers['if-match'] === undefined) ? 'missing If-Match header' + JSON.stringify(req.headers) : 'If-Match header does not match etag ' + req.headers['If-Match'] + ' ' + etag
        lib.badRequest(res, err)
      }
    })
  })
}

function ifAllowedThen(req, res, subject, property, action, callback) {
  lib.ifAllowedThen(req, res, subject, property, action, function() {
    if (property == '_permissions')
      db.withPermissionsDo(req, res, subject, function(permissions, etag) {
        callback(permissions, etag)
      })
    else 
      callback()
  })
}

function addUsersWhoCanSee(req, res, permissions, result, callback) {
  var sharedWith = permissions._sharedWith;
  if (sharedWith !== undefined) {
    for (var i=0; i < sharedWith.length; i++) {
      result[sharedWith[i]] = true;
    }
  }
  var sharingSets = permissions._inheritsPermissionsOf;
  if (sharingSets !== undefined) {
    var count = 0;
    for (let j = 0; j < sharingSets.length; j++) {
      ifAllowedThen(req, res, sharingSets[j], '_permissions', 'read', function(permissions, etag) {
        addUsersWhoCanSee(req, res, permissions, result, function() {if (++count == sharingSets.length) {callback();}});
      });
    }
  } else
    callback()
}

function getUsersWhoCanSee(req, res, resource) {
  var result = {};
  resource = lib.internalizeURL(resource, req.headers.host);
  ifAllowedThen(req, res, resource, '_permissions', 'read', function (permissions, etag) {
    addUsersWhoCanSee(req, res, permissions, result, function() {
      lib.found(req, res, Object.keys(result));
    })
  })
}

function getResourcesSharedWith(req, res, user) {
  var hrstart = process.hrtime();
  console.log(`permissions-maintenance:getResourcesSharedWith:start user: ${JSON.stringify(user)}`)
  var requestingUser = lib.getUser(req);
  user = lib.internalizeURL(user, req.headers.host);
  console.log(user, requestingUser)
  if (user == requestingUser || user == INCOGNITO || (requestingUser !== null && user == ANYONE)) {
    withTeamsDo(req, res, user, function(actors) {
      db.withResourcesSharedWithActorsDo(req, res, actors, function(resources) {
        lib.found(req, res, resources);
        var hrend = process.hrtime(hrstart);
        console.log(`permissions-maintenance:getResourcesSharedWith:success, time: ${hrend[0]}s ${hrend[1]/1000000}ms`);
      });
    });
  } else {
    lib.forbidden(req, res)
  }
}

function getPermissionsHeirs(req, res, securedObject) {
  ifAllowedThen(req, res, securedObject, '_self', 'read', function() {
    db.withHeirsDo(req, res, securedObject, function(heirs) {
      lib.found(req, res, heirs);
    });
  });
}

function withTeamsDo(req, res, user, callback) {
  if (user !== null) {
    user = lib.internalizeURL(user);
    var teamsURL = `/teams?${user.replace('#', '%23')}`
    lib.sendInternalRequest(req, res, teamsURL, 'GET', undefined, function (clientResponse) {
      lib.getClientResponseBody(clientResponse, function(body) {
        if (clientResponse.statusCode == 200) { 
          var actors = JSON.parse(body).contents;
          lib.internalizeURLs(actors, req.headers.host);
          actors.push(user);
          callback(actors);
        } else {
          var err = `withTeamsDo: unable to retrieve ${teamsURL} statusCode ${clientResponse.statusCode} text: ${body}`
          console.log(err)
          lib.internalError(res, err);
        }
      });
    });
  }
}

function requestHandler(req, res) {
  if (req.url == '/permissions')
    if (req.method == 'POST')
      lib.getServerPostObject(req, res, createPermissions)
    else
      lib.methodNotAllowed(req, res, ['POST'])
  else {
    var req_url = url.parse(req.url)
    if (req_url.pathname == '/permissions' && req_url.search !== null)
      if (req.method == 'GET') 
        getPermissions(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host))
      else if (req.method == 'DELETE') 
        deletePermissions(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host))
      else if (req.method == 'PATCH')  
        lib.getServerPostObject(req, res, function(req, res, body) {
          updatePermissions(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host), body)
        })
      else 
        lib.methodNotAllowed(req, res, ['GET', 'PATCH'])
    else if (req_url.pathname == '/resources-shared-with' && req_url.search !== null)
      if (req.method == 'GET')
        getResourcesSharedWith(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host))
      else
        lib.methodNotAllowed(req, res, ['GET'])
    else  if (req_url.pathname == '/permissions-heirs' && req_url.search !== null)
      if (req.method == 'GET') 
        getPermissionsHeirs(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host));
      else
        lib.methodNotAllowed(req, res, ['GET']);
    else if (req_url.pathname == '/users-who-can-access' && req_url.search !== null)
      if (req.method == 'GET')
        getUsersWhoCanSee(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host));
      else
        lib.methodNotAllowed(req, res, ['GET']);
    else
      lib.notFound(req, res);
  }
}

var port = process.env.PORT;
db.init(function(){
  http.createServer(requestHandler).listen(port, function() {
    console.log(`server is listening on ${port} - desperation`);
  });
});
