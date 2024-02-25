#include <common.h>

int DECOMP_VehMath_InterpBySpeed(int val, int speed, int desired)
{
	if(val > desired)
	{
		val -= speed;
		
		if(val < desired)
			return desired;
	}
	
	else
	{
		val += speed;
		
		if(val > desired)
			return desired;
	}
	
	return val;
}