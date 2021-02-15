#include "init.h"

#include "isaac/isaac.h"

void crypto_init()
{
	init_isaac();
}

void crypto_uninit()
{
	uninit_isaac();
}
