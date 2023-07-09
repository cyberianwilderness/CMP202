#pragma once
#include <string>

class userPassword
{
public:
	userPassword();
	~userPassword();

	void setPassword(std::string pwd);
	bool checkPassword(std::string pwd) const;

private:
	std::string password;
};
