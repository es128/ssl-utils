/* jshint node: true */
'use strict';

[
	require('./generate'),
	require('./verify')
].forEach(function (module) {
	Object.keys(module).forEach(function (key) {
		exports[key] = module[key];
	});
});
