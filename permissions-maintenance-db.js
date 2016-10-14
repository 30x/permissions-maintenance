'use strict'
const lib = require('http-helper-functions')
const db = require('./permissions-maintenance-pg.js')

function withErrorHandling(req, res, callback) {
  return function (err) {
    if (err == 404) 
      lib.notFound(req, res)
    else if (err == 409) 
      lib.duplicate(res, 'permissions already exist for this subject')
    else if (err)
      lib.internalError(res, err)
    else 
      callback.apply(this, Array.prototype.slice.call(arguments, 1))
  }
}

function withPermissionsDo(req, res, subject, callback) {
  db.withPermissionsDo(req, subject, withErrorHandling(req, res, callback))
}

function deletePermissionsThen(req, res, subject, callback) {
  db.deletePermissionsThen(req, subject, withErrorHandling(req, res, callback))
}

function createPermissionsThen(req, res, permissions, callback) {
  db.createPermissionsThen(req, permissions, withErrorHandling(req, res, callback))
}

function updatePermissionsThen(req, res, subject, patchedPermissions, etag, callback) {
  db.updatePermissionsThen(req, subject, patchedPermissions, etag, withErrorHandling(req, res, callback))
}

function withResourcesSharedWithActorsDo(req, res, actors, callback) {
  db.withResourcesSharedWithActorsDo(req, actors, withErrorHandling(req, res, callback))
}

function withHeirsDo(req, res, securedObject, callback) {
  db.withHeirsDo(req, securedObject, withErrorHandling(req, res, callback))
}

function init(callback) {
  db.init(callback)    
}

process.on('unhandledRejection', function(e) {
  console.log(e.message, e.stack)
})

exports.withPermissionsDo = withPermissionsDo
exports.createPermissionsThen = createPermissionsThen
exports.deletePermissionsThen = deletePermissionsThen
exports.updatePermissionsThen = updatePermissionsThen
exports.withResourcesSharedWithActorsDo = withResourcesSharedWithActorsDo
exports.withHeirsDo = withHeirsDo
exports.init = init