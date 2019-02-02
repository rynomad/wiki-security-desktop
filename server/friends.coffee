###
 * Federated Wiki : Node Server
 *
 * Copyright Ward Cunningham and other contributors
 * Licensed under the MIT license.
 * https://github.com/fedwiki/wiki-node-server/blob/master/LICENSE.txt
###
# **security.coffee**
# Module for default site security.
#
# This module is not intented for use, but is here to catch a problem with
# configuration of security. It does not provide any authentication, but will
# allow the server to run read-only.

#### Requires ####
console.log 'friends starting'
fs = require 'fs'
require 'seedrandom'
os = require 'os'
jetpack = require 'fs-jetpack'
nacl = require 'tweetnacl'

keys = () -> 
  _box = nacl.box.keyPair()
  _sign = nacl.sign.keyPair()
  box = {
    publicKey : Buffer.from(_box.publicKey).toString('hex'),
    secretKey : Buffer.from(_box.secretKey).toString('hex')
  }
  sign = {
    publicKey : Buffer.from(_sign.publicKey).toString('hex'),
    secretKey : Buffer.from(_sign.secretKey).toString('hex')
  }
  res = {sign, box}
  res



# Export a function that generates security handler
# when called with options object.
module.exports = exports = (log, loga, argv) ->
  console.log("WIKI SECURITY DESKTOP")

  security = {}

  patchCreds = (id, cb) ->
    console.log "patch creds"
    creds = keys()
    console.log creds
    id.box = creds.box
    id.sign = creds.sign
    jetpack.writeAsync(idFile, id).then (err) ->
      if err then return cb err
      console.log("file writen", id)
      owner = id
      cb()

  #### Private utility methods. ####

  user = ''
  owner = ''
  admin = argv.admin

  # save the location of the identity file
  idFile = argv.id

  createOwner = (cb) -> 
    secret = require('crypto').randomBytes(32).toString('hex')
    nick = os.userInfo().username || os.hostname().split('.')[0]
    creds = keys()
    id = {name: nick, friend: {secret: secret}, creds}
    setOwner id, (err) ->
      if err
        console.log 'Failed to claim wiki ', nick, 'error ', err
      cb()

  #### Public stuff ####

  # Retrieve owner infomation from identity file in status directory
  # owner will contain { name: <name>, friend: {secret: '...'}}
  security.retrieveOwner = (cb) ->
    fs.exists idFile, (exists) ->
      if exists
        fs.readFile(idFile, (err, data) ->
          if err then return cb err
          owner = JSON.parse(data)
          console.log '[[[OWNER:' + owner.name + ':' + owner.friend.secret + ':]]]'
          console.log owner, owner.creds
          if owner.box?
            cb()
          else
            patchCreds owner, cb
        )
      else
        console.log('first run create owner')
        createOwner (err) -> 
          security.retrieveOwner(cb)

  # Return the owners name
  security.getOwner = getOwner = ->
    if !owner.name?
      ownerName = ''
    else
      ownerName = owner.name
    ownerName

  security.setOwner = setOwner = (id, cb) ->
    owner = id
    fs.exists idFile, (exists) ->
      if !exists
        jetpack.writeAsync(idFile, id).then (err) ->
          if err then return cb err
          console.log "Claiming site for ", id:id
          owner = id
          cb()
      else
        cb()

  security.getUser = (req) ->
    if req.session.friend
      return req.session.friend
    else
      return ''

  security.isAuthorized = (req) ->
    try
      if req.session.friend is owner.friend.secret
        return true
      else
        return false
    catch error
      return false

  # Wiki server admin
  security.isAdmin = (req) ->
    if req.session.friend is admin
      return true
    else
      return false

  security.logout = () ->
    (req, res) ->
      req.session.reset()
      res.send("OK")

  security.reclaim = () ->
    (req, res) ->
      reclaimCode = ''
      req.on('data', (chunk) ->
        reclaimCode += chunk.toString())

      req.on('end', () ->
        try
          if owner.friend.secret is reclaimCode
            req.session.friend = owner.friend.secret
            res.end()
          else
            res.sendStatus(401)
        catch error
          res.sendStatus(500))

  security.defineRoutes = (app, cors, updateOwner) ->
    app.get '/logout', cors, security.logout()
    app.post '/auth/reclaim/', cors, security.reclaim()

  security
