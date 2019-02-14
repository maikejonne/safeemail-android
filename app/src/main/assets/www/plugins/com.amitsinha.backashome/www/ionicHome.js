cordova.define("com.amitsinha.backashome.ionicHome", function(require, exports, module) {
var exec = require('cordova/exec');
var platform = require('cordova/platform');

module.exports = {
    
    trigger: function(successCallback, errorCallback) {
        exec(successCallback, null, 'IonicHome', 'minimize', [successCallback, errorCallback]);
    }
};
});
