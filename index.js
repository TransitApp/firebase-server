/*
 * firebase-server 0.6.0
 * License: MIT.
 * Copyright (C) 2013, 2014, 2015, 2016, Uri Shaked.
 */

'use strict';

var _ = require('lodash');
var WebSocketServer = require('ws').Server;
var Ruleset = require('targaryen/lib/ruleset');
var RuleDataSnapshot = require('targaryen/lib/rule-data-snapshot');
var firebaseHash = require('./lib/firebaseHash');
var TestableClock = require('./lib/testable-clock');
var TokenValidator = require('./lib/token-validator');
var Promise = require('any-promise');
var firebase = require('firebase');
var _log = require('debug')('firebase-server-' + process.pid);
const EventEmitter = require('events');
var request = require('request');
var cluster = require('cluster');

// In order to produce new Firebase clients that do not conflict with existing
// instances of the Firebase client, each one must have a unique name.
// We use this incrementing number to ensure that each Firebase App name we
// create is unique.
var serverID = 0;

var publicKeyRefreshInterval = 1000 * 60;

function getSnap(ref) {
	return new Promise(function (resolve) {
		ref.once('value', function (snap) {
			resolve(snap);
		});
	});
}

function exportData(ref) {
	return getSnap(ref).then(function (snap) {
		return snap.exportVal();
	});
}

function normalizePath(fullPath) {
	var path = fullPath;
	var isPriorityPath = /\/?\.priority$/.test(path);
	if (isPriorityPath) {
		path = path.replace(/\/?\.priority$/, '');
	}
	return {
		isPriorityPath: isPriorityPath,
		path: path,
		fullPath: fullPath
	};
}

class FirebaseServer extends EventEmitter {
	constructor(port, name, data, isMaster, masterStats) {
		super();
		this.name = name || 'mock.firebase.server';
		this.port = port;
		this.data = data;
		this.isMaster = isMaster || true;
		this.masterStats = masterStats;

		// Firebase is more than just a "database" now; the "realtime database" is
		// just one of many services provided by a Firebase "App" container.
		// The Firebase library must be initialized with an App, and that app
		// must have a name - either a name you choose, or '[DEFAULT]' which
		// the library will substitute for you if you do not provide one.
		// An important aspect of App names is that multiple instances of the
		// Firebase client with the same name will share a local cache instead of
		// talking "through" our server. So to prevent that from happening, we are
		// choosing a probably-unique name that a developer would not choose for
		// their "real" Firebase client instances.
		var appName = 'firebase-server-internal-' + this.name + '-' + process.pid + '-' + serverID++;
		var config;

		if (isMaster) {
			// We must pass a "valid looking" configuration to initializeApp for its
			// internal checks to pass.
			config = {
				databaseURL: 'ws://fakeserver.firebaseio.test',
				serviceAccount: {
					'private_key': 'fake',
					'client_email': 'fake'
				}
			};
			this.app = firebase.initializeApp(config, appName);
			this.app.database().goOffline();
		} else {
			config = {
				databaseURL: 'ws://localhost.firebaseio.test:' + process.env.masterPort
			};
			this.app = firebase.initializeApp(config, appName);
		}

		this.baseRef = this.app.database().ref();

		if (isMaster) {
			this.baseRef.set(data || null);
		}

		this._wss = new WebSocketServer({
			port: port
		});

		this._clock = new TestableClock();

		this.createTokenValidators.bind(this)(function() {
			this._wss.on('connection', this.handleConnection.bind(this));
			var status = isMaster ? 'master' : 'worker';
			_log(`${status} listening for connections on port ${port}`);
		});
	}

	createTokenValidators(callback) {
		var url = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
		var publicKeys = [];
		var validators = {};
		var clock = this.clock;
		var _this = this;

		_log('Getting new public keys from Google');
		request(url, function(err, resp, body) {
			publicKeys = JSON.parse(body);

			_.each(publicKeys, function(value, key) {
				validators[key] = new TokenValidator(value, clock);
			});

			_this._tokenValidators = validators;

			setTimeout(_this.createTokenValidators.bind(_this), publicKeyRefreshInterval);

			if (callback) {
				return callback.bind(_this)();
			}
		});
	}

	handleConnection(ws) {
		_log('New connection from ' + ws._socket.remoteAddress + ':' + ws._socket.remotePort);
		var server = this;
		var authToken = null;

		function send(message) {
			var payload = JSON.stringify(message);
			_log('Sending message: ' + payload);
			try {
				ws.send(payload);
			} catch (e) {
				_log('Send failed: ' + e);
			}
		}

		function authData(decodedToken) {
			if (decodedToken) {
				authToken = decodedToken;
			} else {
				return authToken;
			}
		}

		function pushData(path, data) {
			send({d: {a: 'd', b: {p: path, d: data, t: null}}, t: 'd'});
		}

		function permissionDenied(requestId) {
			send({d: {r: requestId, b: {s: 'permission_denied', d: 'Permission denied'}}, t: 'd'});
		}

		function replaceServerTimestamp(data) {
			if (_.isEqual(data, firebase.database.ServerValue.TIMESTAMP)) {
				return server._clock();
			} else if (_.isObject(data)) {
				return _.mapValues(data, replaceServerTimestamp);
			} else {
				return data;
			}
		}

		function ruleSnapshot(fbRef) {
			return exportData(fbRef.root).then(function (exportVal) {
				return new RuleDataSnapshot(RuleDataSnapshot.convert(exportVal));
			});
		}

		function tryRead(requestId, path, fbRef) {
			if (server._ruleset) {
				return ruleSnapshot(fbRef).then(function (dataSnap) {
					var result = server._ruleset.tryRead(path, dataSnap, authData());
					if (!result.allowed) {
						permissionDenied(requestId);
						throw new Error('Permission denied for client to read from ' + path + ': ' + result.info);
					}
					return true;
				});
			}
			return Promise.resolve(true);
		}

		function tryWrite(requestId, path, fbRef, newData) {
			if (server._ruleset) {
				return ruleSnapshot(fbRef).then(function (dataSnap) {
					var result = server._ruleset.tryWrite(path, dataSnap, newData, authData());
					if (!result.allowed) {
						permissionDenied(requestId);
						throw new Error('Permission denied for client to write to ' + path + ': ' + result.info);
					}
					return true;
				});
			}
			return Promise.resolve(true);
		}

		function handleListen(requestId, normalizedPath, fbRef) {
			var path = normalizedPath.path;
			_log('Client listen ' + path);

			tryRead(requestId, path, fbRef)
				.then(function () {
					var sendOk = true;
					fbRef.on('value', function (snap) {
						if (snap.exportVal()) {
							pushData(path, snap.exportVal());
						}
						if (sendOk) {
							sendOk = false;
							send({d: {r: requestId, b: {s: 'ok', d: {}}}, t: 'd'});
						}
					});
				})
				.catch(_log);
		}

		function handleUpdate(requestId, normalizedPath, fbRef, newData) {
			var path = normalizedPath.path;
			_log('Client update ' + path);

			newData = replaceServerTimestamp(newData);

			var checkPermission = Promise.resolve(true);

			if (server._ruleset) {
				checkPermission = exportData(fbRef).then(function (currentData) {
					var mergedData = _.assign(currentData, newData);
					return tryWrite(requestId, path, fbRef, mergedData);
				});
			}

			checkPermission.then(function () {
				fbRef.update(newData);
				server.emit('update', path, newData);
				send({d: {r: requestId, b: {s: 'ok', d: {}}}, t: 'd'});
			}).catch(_log);
		}

		function handleSet(requestId, normalizedPath, fbRef, newData, hash) {
			_log('Client set ' + normalizedPath.fullPath);

			var progress = Promise.resolve(true);
			var path = normalizedPath.path;

			newData = replaceServerTimestamp(newData);

			if (normalizedPath.isPriorityPath) {
				progress = exportData(fbRef).then(function (parentData) {
					if (_.isObject(parentData)) {
						parentData['.priority'] = newData;
					} else {
						parentData = {
							'.value': parentData,
							'.priority': newData
						};
					}
					newData = parentData;
				});
			}

			progress = progress.then(function () {
				return tryWrite(requestId, path, fbRef, newData);
			});

			if (typeof hash !== 'undefined') {
				progress = progress.then(function () {
					return getSnap(fbRef);
				}).then(function (snap) {
					var calculatedHash = firebaseHash(snap.exportVal());
					if (hash !== calculatedHash) {
						pushData(path, snap.exportVal());
						send({d: {r: requestId, b: {s: 'datastale', d: 'Transaction hash does not match'}}, t: 'd'});
						throw new Error('Transaction hash does not match: ' + hash + ' !== ' + calculatedHash);
					}
				});
			}

			progress.then(function () {
				fbRef.set(newData);
				server.emit('set', normalizedPath.fullPath, newData);
				fbRef.once('value', function (snap) {
					pushData(path, snap.exportVal());
					send({d: {r: requestId, b: {s: 'ok', d: {}}}, t: 'd'});
				});
			}).catch(_log);
		}

		function handleAuth(requestId, credential) {
			// Utility functions
			function base64urlDecode(str) {
			  return new Buffer(base64urlUnescape(str), 'base64').toString();
			}

			function base64urlUnescape(str) {
			  str += new Array(5 - str.length % 4).join('=');
			  return str.replace(/\-/g, '+').replace(/_/g, '/');
			}

			if (server._authSecret === credential) {
				return send({t: 'd', d: {r: requestId, b: {s: 'ok', d: TokenValidator.normalize({ auth: null, admin: true, exp: null }) }}});
			}

			try {
				// Get the header segment from the credentials
				// Get the 'kid' from the header and choose the correct token validator
				var headerSeg = credential.split('.')[0],
						header = JSON.parse(base64urlDecode(headerSeg)),
						tokenValidator = server._tokenValidators[header.kid];

				var decoded = tokenValidator.decode(credential);
				authData(decoded); // Store the decoded credential

				send({t: 'd', d: {r: requestId, b: {s: 'ok', d: TokenValidator.normalize(decoded)}}});
			} catch (e) {
				send({t: 'd', d: {r: requestId, b: {s: 'invalid_token', d: 'Could not parse auth token.'}}});
			}
		}

		function accumulateFrames(data){
			//Accumulate buffer until websocket frame is complete
			if (typeof ws.frameBuffer == 'undefined'){
				ws.frameBuffer = '';
			}

			try {
				var parsed = JSON.parse(ws.frameBuffer + data);
				ws.frameBuffer = '';
				return parsed;
			} catch(e) {
				ws.frameBuffer += data;
			}

			return '';
		}

		ws.on('message', function (data) {
			if (cluster.isWorker) {
				_log('Sending');
				process.send({pid: process.pid});
			} else {
				this.masterStats();
			}

			_log('Client message: ' + data);
			if (data === 0) {
				return;
			}

			var parsed = accumulateFrames(data);

			if (parsed && parsed.t === 'd') {
				var path;
				if (typeof parsed.d.b.p !== 'undefined') {
					path = parsed.d.b.p.substr(1);
				}
				path = normalizePath(path || '');
				var requestId = parsed.d.r;
				var fbRef = path.path ? this.baseRef.child(path.path) : this.baseRef;
				if (parsed.d.a === 'l' || parsed.d.a === 'q') {
					handleListen(requestId, path, fbRef);
				}
				if (parsed.d.a === 'm') {
					handleUpdate(requestId, path, fbRef, parsed.d.b.d);
				}
				if (parsed.d.a === 'p') {
					handleSet(requestId, path, fbRef, parsed.d.b.d, parsed.d.b.h);
				}
				if (parsed.d.a === 'auth' || parsed.d.a === 'gauth') {
					handleAuth(requestId, parsed.d.b.cred);
				}
			}
		}.bind(this));

		send({d: {t: 'h', d: {ts: new Date().getTime(), v: '5', h: this.name, s: ''}}, t: 'c'});
	}

	setRules (rules) {
		this._ruleset = new Ruleset(rules);
	}

	getData (ref) {
		console.warn('FirebaseServer.getData() is deprecated! Please use FirebaseServer.getValue() instead'); // eslint-disable-line no-console
		var result = null;
		this.baseRef.once('value', function (snap) {
			result = snap.val();
		});
		return result;
	}

	getSnap (ref) {
		return getSnap(ref || this.baseRef);
	}

	getValue (ref) {
		return this.getSnap(ref).then(function (snap) {
			return snap.val();
		});
	}

	exportData (ref) {
		return exportData(ref || this.baseRef);
	}

	close (callback) {
		this._wss.close(callback);
	}

	setTime (newTime) {
		this._clock.setTime(newTime);
	}

	setAuthSecret (newSecret) {
		this._authSecret = newSecret;
		// We're not using auth secrets anymore
		// this._tokenValidator.setSecret(newSecret);
	}
	
	database() {
		return this.app.database();
	}
}

module.exports = FirebaseServer;
