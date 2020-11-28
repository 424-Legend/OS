// #include <stdio.h>
// #include <string.h>
// #include <stdlib.h>

// int main(){
//     char* save_ptr;
//     char* str;
//     char* test;
//     str = "you are crazy ";
//     for(; save_ptr != NULL;){
//         printf("1\n");
//         printf("%s\n",strtok_r(str," ",&save_ptr));
//         // str = save_ptr;
//     }
//     return 0;
// }


#include <stdio.h>  
#include <time.h>  
#include <stdlib.h>  
#include <string.h>  
#include <unistd.h>
 
int main()
{
	char *pchSrc = "Can I help  you ";
	char chBuffer[102] ;
	char *pchDilem = " ";
	char *pchStrTmpIn = NULL;
	char *pchTmp = NULL;
	strncpy(chBuffer,pchSrc ,sizeof(chBuffer) - 1);
	pchTmp = chBuffer;
	while(NULL != ( pchTmp = strtok_r( pchTmp, pchDilem, &pchStrTmpIn) ))
	{
		printf("\n pchTmp[%s] pchStrTmpIn[%s]\n",pchTmp,pchStrTmpIn);
	//	printf("\n pchTmp[%s] \n",pchTmp);
		pchTmp = NULL;
	}
	return 0;}
    