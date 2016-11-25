'use strict';
var Pool = require('pg').Pool;
var lib = require('http-helper-functions');
var pge = require('pg-event-producer');

var ANYONE = 'http://apigee.com/users/anyone';
var INCOGNITO = 'http://apigee.com/users/incognito';

var config = {
  host: process.env.PG_HOST,
  user: process.env.PG_USER,
  password: process.env.PG_PASSWORD,
  database: process.env.PG_DATABASE
};

var pool = new Pool(config);
var eventProducer = new pge.eventProducer(pool);

function withPermissionsDo(req, subject, callback) {
  var query = 'SELECT etag, data FROM permissions WHERE subject = $1';
  pool.query(query,[subject], function (err, pgResult) {
    if (err)
      callback(err)
    else {
      if (pgResult.rowCount === 0) 
        callback(404)
      else {
        var row = pgResult.rows[0];
        callback(null, row.data, row.etag)
      }
    }
  });
}

function deletePermissionsThen(req, subject, callback) {
  var query = `DELETE FROM permissions WHERE subject = '${subject}' RETURNING *`;
  function eventData(pgResult) {
    return {subject: subject, action: 'delete', etag: pgResult.rows[0].etag}
  }
  eventProducer.queryAndStoreEvent(req, query, 'permissions', eventData, function(err, pgResult, pgEventResult) {
    if (err) 
      callback(err) 
    else 
      callback(err, pgResult.rows[0].data, pgResult.rows[0].etag)
  });

}

function createPermissionsThen(req, permissions, callback) {
  var subject = permissions._subject;
  var query = `INSERT INTO permissions (subject, etag, data) values('${subject}', 1, '${JSON.stringify(permissions)}') RETURNING etag`;
  function eventData(pgResult) {
    return {subject: permissions._subject, action: 'create', etag: pgResult.rows[0].etag}
  }
  eventProducer.queryAndStoreEvent(req, query, 'permissions', eventData, function(err, pgResult, pgEventResult) {
    if (err) 
      if (err.code == 23505)
        callback(409)
      else
        callback(err) 
    else 
      callback(err, pgResult.rows[0].etag)
  });
}

function updatePermissionsThen(req, subject, patchedPermissions, etag, callback) {
  var key = lib.internalizeURL(subject, req.headers.host);
  var query = `UPDATE permissions SET (etag, data) = (${(etag+1) % 2147483647}, '${JSON.stringify(patchedPermissions)}') WHERE subject = '${key}' AND etag = ${etag} RETURNING etag`;
  function eventData(pgResult) {
    return {subject: patchedPermissions._subject, action: 'update', etag: pgResult.rows[0].etag}
  }
  eventProducer.queryAndStoreEvent(req, query, 'permissions', eventData, function(err, pgResult, pgEventResult) {
    if (err) 
      callback(err) 
    else 
      callback(err, pgResult.rows[0].etag);
  })
}

function withResourcesSharedWithActorsDo(req, actors, callback) {
  actors = actors == null ? [INCOGNITO] : actors.concat([INCOGNITO, ANYONE]);
  var query = `SELECT DISTINCT subject FROM permissions, jsonb_array_elements(permissions.data#>'{_metadata, sharedWith}')
               AS sharedWith WHERE sharedWith <@ '${JSON.stringify(actors)}'`; // was jsonb_array_elements(permissions.data->'_sharedWith') 
  pool.query(query, function (err, pgResult) {
    if (err) 
      callback(err) 
    else 
      callback(err, pgResult.rows.map(row => row.subject))
  });
}

function withHeirsDo(req, securedObject, callback) {
  var query = `SELECT subject, data FROM permissions WHERE data @> '{"_inheritsPermissionsOf":["${securedObject}"]}'`
  pool.query(query, function (err, pgResult) {
    if (err) 
      callback(err) 
    else 
      callback(null, pgResult.rows.map(row => row.data._subject))
  })
}

function init(callback) {
  var query = 'CREATE TABLE IF NOT EXISTS permissions (subject text primary key, etag int, data jsonb);'
  pool.query(query, function(err, pgResult) {
    if(err)
      console.error('error creating permissions table', err);
    else {
      console.log('permissions-maintenance-db: connected to PG, config: ', config);
      eventProducer.init(callback);
    }
  })    
}

exports.withPermissionsDo = withPermissionsDo
exports.createPermissionsThen = createPermissionsThen
exports.deletePermissionsThen = deletePermissionsThen
exports.updatePermissionsThen = updatePermissionsThen
exports.withResourcesSharedWithActorsDo = withResourcesSharedWithActorsDo
exports.withHeirsDo = withHeirsDo
exports.init = init