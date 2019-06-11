#include <stdio.h>
#include <time.h>
int main()
{
        while(1){
                sleep(10);
                printf("%d : original\n",time(0));
        }
		return 0;
}
