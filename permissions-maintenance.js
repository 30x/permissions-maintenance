'use strict'
/* 
We dislike prerequisites and avoid them where possible. We especially dislike prereqs that have a 'framework' style; 
simple libraries are more palatable.
Please do not add any framework to this preqs. We do not want express or anything like it. We do not want any sort of "ORM" or similar.
Adding simple library prereqs could be OK if the value they bring is in proportion to their size and complexity 
and is warranted by the difficulty of the problem being solved.
*/
const http = require('http')
const url = require('url')
const querystring = require('querystring')
const lib = require('http-helper-functions')
const pLib = require('permissions-helper-functions')
const rLib = require('response-helper-functions')
const db = require('./permissions-maintenance-db.js')

var INTERNAL_SCHEME = process.env.INTERNAL_SCHEME || 'http'
var ANYONE = 'http://apigee.com/users/anyone'
var INCOGNITO = 'http://apigee.com/users/incognito'
var SHIPYARD_PRIVATE_SECRET = process.env.SHIPYARD_PRIVATE_SECRET
if (SHIPYARD_PRIVATE_SECRET !== undefined) {
  SHIPYARD_PRIVATE_SECRET = new Buffer(SHIPYARD_PRIVATE_SECRET).toString('base64')
}

function log(method, text) {
  console.log(Date.now(), process.env.COMPONENT_NAME, method, text)
}

function verifyPermissions(req, res, permissions, callback) {
  if (permissions._subject === undefined) 
    return 'invalid JSON: "_subject" property not set'
  if (permissions._inheritsPermissionsOf !== undefined && !Array.isArray(permissions._inheritsPermissionsOf))
    return '_inheritsPermissionsOf must be an Array'
  var permissionsSelf = permissions._self
  var user = lib.getUser(req.headers.authorization)
  if (permissions._inheritsPermissionsOf === undefined) 
    if (permissionsSelf === undefined || permissionsSelf.govern === undefined)
      rLib.badRequest(res, `permissions for ${permissions._subject} must specify inheritance or at least one governor`)
    else
      if (permissionsSelf.admin === undefined)
        permissionsSelf.admin = permissionsSelf.govern
  permissions._metadata = {}
  var rslt = lib.setStandardCreationProperties(req, permissions._metadata, user)
  if (rslt)
    return rLib.badRequest(res, rslt)
  calculateSharedWith(req, permissions)
  addCalculatedProperties(req, permissions)

  var sharingSets = permissions._inheritsPermissionsOf
  if (sharingSets !== undefined && sharingSets.length > 0) {
    sharingSets = sharingSets.map(x => lib.internalizeURL(x))
    var subject = lib.internalizeURL(permissions._subject)
    if (sharingSets.indexOf(subject) == -1) {
      var count = 0
      for (var i=0; i < sharingSets.length; i++) {
        var sharingSet = sharingSets[i]
        var allowedByAll = true
        pLib.withAllowedDo(lib.flowThroughHeaders(req), res, sharingSet, '_permissionsHeirs', 'add', function(allowed) {
          allowedByAll = allowedByAll && allowed
          if (++count == sharingSets.length) 
            if (allowedByAll)
              callback()
            else
              rLib.forbidden(res, `user ${user} is not allowed to inherit permissions from ${sharingSets}`)
        })
      }
    } else
      rLib.badRequest(res, `cannot inherit from self: ${subject} inheritsFrom: ${sharingSets}`)
  } else
    callback()
}

function calculateSharedWith(req, permissions) {
  function listUsers (obj, result) {
    for (var operation in obj) {
      var actors = obj[operation]
      if (actors !== undefined)
        for (var j = 0; j < actors.length; j++) 
          result[actors[j]] = true
    }
  }
  var result = {}
  if (permissions._self) 
    listUsers(permissions._self, result)
  permissions._metadata.sharedWith = Object.keys(result)
}

function createPermissions(req, res, permissions) {
  var hrstart = process.hrtime()
  log('createPermissions', 'start')
  function primCreate(req, res, permissions, scopes) {
    db.createPermissionsThen(req, res, permissions, scopes, function(etag) {
      var permissionsURL =  `${rLib.INTERNAL_URL_PREFIX}/permissions?${permissions._subject}`
      rLib.created(res, permissions, req.headers.accept, permissionsURL, etag)
      var hrend = process.hrtime(hrstart)
      log('createPermissions', `success, time: ${hrend[0]}s ${hrend[1]/1000000}ms`)
    })        
  }
  pLib.ifAllowedThen(lib.flowThroughHeaders(req), res, '/', 'permissions', 'create', function() {
    var ancestors = permissions._inheritsPermissionsOf
    if (ancestors)
      ifAllowedToInheritFromThen(req, res, null, ancestors, function(scopes) {
        console.log('\n\nancestors', ancestors, 'scopes', scopes, '\n\n')
        verifyPermissions(req, res, permissions, () => primCreate(req, res, permissions, scopes))
      })
    else
      verifyPermissions(req, res, permissions, () => primCreate(req, res, permissions, []))      
  })
}

function addCalculatedProperties(req, permissions) {
}

function getPermissions(req, res, subject) {
  var hrstart = process.hrtime()
  log('getPermissions:', `start subject: ${subject}`)
  db.withPermissionsDo(req, res, subject, function(permissions, etag) {
    pLib.ifAllowedThen(lib.flowThroughHeaders(req), res, subject, '_self', 'admin', function() {
      addCalculatedProperties(req, permissions)
      rLib.found(res, permissions, req.headers.accept, `/permissins?${subject}`, etag)
      var hrend = process.hrtime(hrstart)
      log('getPermissions', `success, time: ${hrend[0]}s ${hrend[1]/1000000}ms`)
    })
  })  
}

function deletePermissions(req, res, subject) {
  var hrstart = process.hrtime()
  log('deletePermissions', `start subject: ${subject}`)
  pLib.ifAllowedThen(lib.flowThroughHeaders(req), res, subject, '_self', 'govern', function() {
    db.deletePermissionsThen(req, res, subject, function(permissions, etag) {
      addCalculatedProperties(req, permissions)
      rLib.found(res, permissions, req.headers.accept, `/permissins?${subject}`, etag)
      var hrend = process.hrtime(hrstart)
      log('deletePermissions', `success, time: ${hrend[0]}s ${hrend[1]/1000000}ms`)
    })
  })
}

function ifAllowedToInheritFromThen(req, res, subject, sharingSets, callback) {
  if (sharingSets.indexOf(subject) > -1)
    rLib.badRequest(res, 'may not inherit permissions from self')
  else {
    var queryParams = sharingSets.map(x => `sharingSet=${x}`)
    if (subject)
      queryParams.push(`subject=${subject}`)
    if (queryParams.length > 0) {
      var path = `/is-allowed-to-inherit-from?${queryParams.join('&')}`
      lib.sendInternalRequestThen(res, 'GET', path, lib.flowThroughHeaders(req), null, function(clientResponse) {
        lib.getClientResponseBody(clientResponse, function(body) {
          if (clientResponse.statusCode == 200) { 
            var result = JSON.parse(body)
            if (result.allowed == true)
              callback(result.scopes)
            else
              rLib.badRequest(res, `may not inherit from ${sharingSets}`)
          } else {
            var err = `ifAllowedToInheritFromThen: unable to retrieve ${path} statusCode ${clientResponse.statusCode} text: ${body}`
            log('ifAllowedToInheritFromThen', err)
            rLib.internalError(res, err)
          }
        })
      })
    } else
      callback([])
  }
}

function updatePermissions(req, res, subject, patch) {
  var hrstart = process.hrtime()
  log('updatePermissions', `start subject: ${subject}`)
  db.withPermissionsDo(req, res, subject, function(permissions, etag) {
    pLib.ifAllowedThen(lib.flowThroughHeaders(req), res, subject, '_self', 'govern', function() {
      lib.applyPatch(req, res, permissions, patch, function(patchedPermissions) {
        if (req.headers['if-match'] == etag) { 
          var new_permissions = '_inheritsPermissionsOf' in patchedPermissions ? patchedPermissions._inheritsPermissionsOf : []
          ifAllowedToInheritFromThen(req, res, subject, new_permissions, function(scopes) {
            verifyPermissions(req, res, patchedPermissions, function() {
              patchedPermissions._metadata.modifier = lib.getUser(req.headers.authorization)
              patchedPermissions._metadata.modified = new Date().toISOString()
              db.updatePermissionsThen(req, res, subject, patchedPermissions, scopes, etag, function(etag) {
                rLib.found(res, patchedPermissions, req.headers.accept, `/permissins?${subject}`, etag)
                var hrend = process.hrtime(hrstart)
                log('updatePermissions', `success, time: ${hrend[0]}s ${hrend[1]/1000000}ms`)
              })
            })
          })
        } else {
          var err = (req.headers['if-match'] === undefined) ? 'missing If-Match header' : 'If-Match header does not match etag ' + req.headers['If-Match'] + ' ' + etag
          rLib.badRequest(res, err)
        }
      })
    })
  })
}

function putPermissions(req, res, subject, permissions) {
  var hrstart = process.hrtime()
  log('putPermissions', `start subject: ${subject}`)
  pLib.ifAllowedThen(lib.flowThroughHeaders(req), res, subject, '_self', 'govern', function() {
    var new_ancestors = '_inheritsPermissionsOf' in permissions ? permissions._inheritsPermissionsOf : []
    ifAllowedToInheritFromThen(req, res, subject, new_ancestors, function(scopes) {
      verifyPermissions(req, res, permissions, function () {
        calculateSharedWith(req, permissions)
        permissions._metadata.modifier = lib.getUser(req.headers.authorization)
        permissions._metadata.modified = new Date().toISOString()
        db.putPermissionsThen(req, res, subject, permissions, scopes, function(etag) {
          addCalculatedProperties(req, permissions) 
          rLib.found(res, permissions, req.headers.accept, `/permissins?${subject}`, etag)
          var hrend = process.hrtime(hrstart)
          log('putPermissions', `success, time: ${hrend[0]}s ${hrend[1]/1000000}ms`)
        })
      })
    })
  })
}

function getUsersWhoCanAccess(req, res, subject) {
  function addUsersWhoCanAcess(req, res, permissions, result, callback) {
    var sharedWith = permissions._metadata.sharedWith
    if (sharedWith !== undefined)
      for (var i=0; i < sharedWith.length; i++)
        result[sharedWith[i]] = true
    var sharingSets = permissions._inheritsPermissionsOf
    if (sharingSets !== undefined) {
      var count = 0
      for (let j = 0; j < sharingSets.length; j++) 
        db.withPermissionsDo(req, res, sharingSets[j], function(permissions, etag) {
          pLib.ifAllowedThen(lib.flowThroughHeaders(req), res, sharingSets[j], '_self', 'admin', function() {
            addUsersWhoCanAcess(req, res, permissions, result, function() {
              if (++count == sharingSets.length) {callback()}
            })
          })
        })
    } else
      callback()
  }
  var result = {}
  subject = lib.internalizeURL(subject, req.headers.host)
  db.withPermissionsDo(req, res, subject, function(permissions, etag) {
    pLib.ifAllowedThen(lib.flowThroughHeaders(req), res, subject, '_self', 'admin', function() {
      addUsersWhoCanAcess(req, res, permissions, result, function() {
        rLib.found(res, Object.keys(result), req.headers.accept, req.url)
      })
    })
  })
}

function getResourcesSharedWith(req, res, user) {
  var hrstart = process.hrtime()
  log('getResourcesSharedWith', `start user: ${JSON.stringify(user)}`)
  var requestingUser = lib.getUser(req.headers.authorization)
  user = lib.internalizeURL(user, req.headers.host)
  if (user == requestingUser || user == INCOGNITO || (requestingUser !== null && user == ANYONE))
    withTeamsDo(req, res, user, function(actors) {
      db.withResourcesSharedWithActorsDo(req, res, actors, function(resources) {
        rLib.found(res, resources, req.headers.accept, req.url)
        var hrend = process.hrtime(hrstart)
        log('getResourcesSharedWith', `success, time: ${hrend[0]}s ${hrend[1]/1000000}ms`)
      })
    })
  else
    rLib.forbidden(res, `user ${user} may not access ${req.url}`)
}

function getResourcesSharedWithTeamTransitively(req, res, team) {
  var hrstart = process.hrtime()
  log('getResourcesSharedWithTeamTransitively', `start team: ${team}`)
  function withHeirsRecursive(req, res, resources, result, callback) {
    db.withHeirsDo(req, res, resources, function(heirs) {
      if (heirs.length > 0) {
        heirs = heirs.filter(heir => result.indexOf(heir) == -1)
        for (let i = 0; i < heirs.length; i++) 
          result.push(heirs[i])
        withHeirsRecursive(req, res, heirs, result, function(){
          callback(result)                
        })
      } else
        callback(result)
    })
  }
  pLib.ifAllowedThen(lib.flowThroughHeaders(req), res, team, '_self', 'update', function() {
    db.withResourcesSharedWithActorsDo(req, res, [team], function(resources) {
      var envelope = {
        kind: 'Collection',
        self: req.url
      }
      if (resources.length > 0) {
        var result = resources.slice()
        withHeirsRecursive(req, res, resources, result, function(){
          envelope.contents = result
          lrLibib.found(res, envelope, req.headers.accept, req.url)
          var hrend = process.hrtime(hrstart)
          log('getResourcesSharedWithTeamTransitively', `success, time: ${hrend[0]}s ${hrend[1]/1000000}ms`)
        })
      } else {
        envelope.contents = resources
        lirLibb.found(res, envelope, req.headers.accept, req.url)
        var hrend = process.hrtime(hrstart)
        log('getResourcesSharedWithTeamTransitively', `success, time: ${hrend[0]}s ${hrend[1]/1000000}ms`)
      }        
    })
  })
}

function getPermissionsHeirs(req, res, subject) {
  pLib.ifAllowedThen(lib.flowThroughHeaders(req), res, subject, '_self', 'read', function() {
    db.withHeirsDo(req, res, subject, function(heirs) {
      var body = {
        kind: "Collection",
        self: req.url,
        contents: heirs
      }
      rLib.found(res, body, req.headers.accept, req.url)
    })
  })
}

function getPermissionsHeirsDetails(req, res, queryString) {
  var params = querystring.parse(queryString)
  var subject = params.resource
  var properties = params.property ? (Array.isArray(params.property) ? params.property : [params.property]) : []
  log('getPermissionsHeirsDetails', `start subject: ${subject}`)
  if (properties.length == 0)
    getPermissionsHeirs(req, res, subject)
  else
    pLib.ifAllowedThen(lib.flowThroughHeaders(req), res, subject, '_self', 'read', function() {
      db.withHeirsDo(req, res, subject, function(heirs) {
        var heirsDetails = []
        var result = {
          kind: "Collection",
          self: req.url,
          contents: heirsDetails
        }
        if (heirs.length > 0) {
          var includeSharedWith = properties.indexOf('_sharedWith') > -1 || properties.indexOf('_sharedWithCount') > -1
          var db_count = includeSharedWith ? 0 : heirs.length
          var http_count = 0
          for (let i=0; i < heirs.length; i++) {
            let heir = lib.externalizeURLs(url.resolve(`http://${req.headers.host}${req.url}`, heirs[i]))
            heirsDetails[i] = {self: heir}
            if (includeSharedWith)
              db.db.withPermissionsDo(req, subject, function(err, permissions) {
                if (!err) {
                  if (properties.indexOf('_sharedWith') > -1)
                    heirsDetails[i]._sharedWith = permissions._metadata.sharedWith
                  if (properties.indexOf('_sharedWithCount') > -1)
                    heirsDetails[i]._sharedWithCount = permissions._metadata.sharedWith.length
                }
                if (++db_count == heirs.length && http_count == heirs.length)
                  rLib.found(res, result, req.headers.accept, req.url)
              })  
            if (properties.length > 0)
              lib.sendInternalRequest('GET', heirs[i], lib.flowThroughHeaders(req), null, function(err, clientRes) {
                if (err) {
                  if (++http_count == heirs.length && db_count == heirs.length)
                    rLib.found(res, result, req.headers.accept, req.url)
                } else 
                  lib.getClientResponseBody(clientRes, function (body) {
                    try {
                      var parsedData = JSON.parse(body);
                    } catch (e) {
                      log('getPermissionsHeirsDetails', e.message);
                    }
                    if (clientRes.statusCode == 200 && parsedData) { 
                      var heirsDetail = heirsDetails[i]
                      for (var j = 0; j < properties.length; j++) {
                        var property = properties[j]
                        if (property in parsedData)
                          heirsDetail[property] = parsedData[property]
                      }
                    }
                    if (++http_count == heirs.length && db_count == heirs.length)
                      rLib.found(res, result, req.headers.accept, req.url)
                  })              
              })
          }
        } else
          rLib.found(res, result, req.headers.accept, req.url)
      })
    })
}

function withTeamsDo(req, res, user, callback) {
  if (user !== null) {
    user = lib.internalizeURL(user)
    var teamsURL = `/teams?${user.replace('#', '%23')}`
    lib.sendInternalRequestThen(res, 'GET', teamsURL, lib.flowThroughHeaders(req), undefined, function (clientResponse) {
      lib.getClientResponseBody(clientResponse, function(body) {
        if (clientResponse.statusCode == 200) { 
          var actors = JSON.parse(body).contents
          lib.internalizeURLs(actors, req.headers.host)
          actors.push(user)
          callback(actors)
        } else {
          var err = `withTeamsDo: unable to retrieve ${teamsURL} statusCode ${clientResponse.statusCode} text: ${body}`
          log('withTeamsDo', err)
          rLib.internalError(res, err)
        }
      })
    })
  }
}

function requestHandler(req, res) {
  if (req.url == '/permissions')
    if (req.method == 'POST')
      lib.getServerPostObject(req, res, (p) => createPermissions(req, res, p))
    else
      rLib.methodNotAllowed(res, ['POST'])
  else {
    var req_url = url.parse(req.url)
    if (req_url.pathname == '/permissions' && req_url.search !== null)
      if (req.method == 'GET') 
        getPermissions(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host))
      else if (req.method == 'DELETE') 
        deletePermissions(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host))
      else if (req.method == 'PATCH')  
        lib.getServerPostObject(req, res, (body) => updatePermissions(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host), body))
      else if (req.method == 'PUT')  
        lib.getServerPostObject(req, res, (body) => putPermissions(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host), body))
      else 
        rLib.methodNotAllowed(res, ['GET', 'PATCH', 'PUT'])
    else if (req_url.pathname == '/resources-accessible-by-team-members' && req_url.search !== null)
      if (req.method == 'GET')
        getResourcesSharedWithTeamTransitively(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host))
      else
        rLib.methodNotAllowed(res, ['GET'])
    else if (req_url.pathname == '/resources-shared-with' && req_url.search !== null)
      if (req.method == 'GET')
        getResourcesSharedWith(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host))
      else
        rLib.methodNotAllowed(res, ['GET'])
    else if (req_url.pathname == '/permissions-heirs' && req_url.search !== null)
      if (req.method == 'GET') 
        getPermissionsHeirs(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host))
      else
        rLib.methodNotAllowed(res, ['GET'])
    else if (req_url.pathname == '/permissions-heirs-details' && req_url.search !== null) 
      if (req.method == 'GET') 
        getPermissionsHeirsDetails(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host))
      else
        rLib.methodNotAllowed(res, ['GET'])
    else if (req_url.pathname == '/users-who-can-access' && req_url.search !== null)
      if (req.method == 'GET')
        getUsersWhoCanAccess(req, res, lib.internalizeURL(req_url.search.substring(1), req.headers.host))
      else
        rLib.methodNotAllowed(res, ['GET'])
    else
      rLib.notFound(res, `//${req.headers.host}${req.url} not found`)
  }
}

var port = process.env.PORT
function start(){
  db.init(function(){
    http.createServer(requestHandler).listen(port, function() {
      log('start', `server is listening on ${port}`)
    })
  })
}

if (process.env.INTERNAL_SY_ROUTER_HOST == 'kubernetes_host_ip') 
  lib.getHostIPThen(function(err, hostIP){
    if (err) 
      process.exit(1)
    else {
      process.env.INTERNAL_SY_ROUTER_HOST = hostIP
      start()
    }
  })
else 
  start()