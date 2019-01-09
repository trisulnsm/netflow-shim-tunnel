#include "PrintErrno.h"
#include <string.h>
#include <stdexcept>

CPrintErrno::CPrintErrno(int eno)
: errcode(eno)
{
	enum {ERRBUF_SIZE=512};
	char errbuf[ERRBUF_SIZE];
	tserror=strerror_r(eno,errbuf,ERRBUF_SIZE-1);
}

void CPrintErrno::throw_runtime_exception()
{
	throw std::runtime_error(tserror);
}


void CPrintErrno::throw_runtime_exception(const std::string& extramsg)
{
	throw std::runtime_error(tserror + " : " + extramsg);
}
