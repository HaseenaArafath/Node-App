const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

// User Schema
var UserSchema = mongoose.Schema({
	username: {
		type: String,
		index:true
	},
	password: {
		type: String
	},
	email: {
		type: String
	},
	name: {
		type: String
	}
});

var User = module.exports = mongoose.model('User', UserSchema);

module.exports.createMember = function(newUser, callback){
	bcrypt.genSalt(10, function(err, salt) {
	    bcrypt.hash(newUser.password, salt, function(err, hash) {
	        newUser.password = hash;
	        newUser.save(callback);
	    });
	});
}

module.exports.getMemberByUsername = function(username, callback){
	var query = {username: username};
	User.findOne(query, callback);
}

module.exports.getMemberById = function(id, callback){
	User.findById(id, callback);
}

module.exports.validatePassword = function(candidatePassword, hash, callback){
	bcrypt.compare(candidatePassword, hash, function(err, isMatch) {
    	if(err) throw err;
    	callback(null, isMatch);
	});
}