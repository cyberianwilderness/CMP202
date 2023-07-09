#include "userPassword.h"

userPassword::userPassword() { }
userPassword::~userPassword() { }

void userPassword::setPassword(std::string pwd) {
	password = pwd;		//sets the password of the user
}

bool userPassword::checkPassword(std::string pwd) const {
	if (pwd == password) { 
		return true;
	}
	else {
		return false;
	}
}
