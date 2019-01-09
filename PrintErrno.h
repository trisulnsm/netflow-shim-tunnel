#pragma once 

#include <errno.h>
#include <string>

class CPrintErrno
{
	


public:
	CPrintErrno(int eno);

public:
	const std::string&  what() const  { return tserror;} 
	int	    		code() const  { return errcode;}
	void			throw_runtime_exception();
	void			throw_runtime_exception(const std::string& extramsg);
	

private:
	std::string		tserror;
	int 		errcode;

};


