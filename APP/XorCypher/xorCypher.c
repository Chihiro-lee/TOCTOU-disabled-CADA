#include <RAhook.h>

#define cr              '\r'
// Simulate non-attack input
char user_input[5] = {1, 2, 3, 4, '\r'};
char verify_entry = 0;
const char key1[] = "fioeosijiefi435jf394f93c9m3m9230cm293e48";
void encrypt(char* str, int length);

#define KEY_LENGTH 40

void waitForInput(){
    char entry[5] = {0, 0, 0, 0};
    verify_entry = read_data(entry);
}

int read_data(char * entry){
    int  i = 0;
    while(user_input[i] != cr){
        *(entry+i) = user_input[i];
        i++;
    }
    char entryCode[5]= {1, 2, 3, 4};
    int j = 0;
    while(j < 4){
        if(entry[j] != entryCode[j]){
            return 0;
        }
        j++;
    }
    return 1;
}

int main(void)
{
    WDTCTL = WDTPW | WDTHOLD;   // stop watchdog timer
    P4DIR |= BIT2; //Set up also analyser
    P4OUT |= BIT2; //Start logical analyser
    waitForInput();
    if (verify_entry){
        long encodings = 10;
        char str1[] = "Hi, this is a test string. It's purpose is to test the functionig of the xor function";//String of length 245 chars + terminating char
        char str2[] = "GoodEvening, this is yet another test string. As for the other string, also this one must be used to test the crypto function";
        int len1 = 85; //characters
        int len2 = 125; //chars
        long i = 0;
        while(i<encodings){
        //Encrypt 1
        encrypt(str1,len1);
        /*for(int j = 0; j < len1; j++){
            str1[j] ^= key[j%KEY_LENGTH];
        }*/
        //Encrypt 2
        encrypt(str2,len2);
        i++;
        } 
        P4OUT &= (~BIT2); //Stop analyser
    }
    else
        P1OUT = 0x00;
    
    //register unsigned int stop = TA0R; // Stop timer
    return 0;
}

void encrypt(char* str, int length){
    for(int j = 0; j < length; j++){
        str[j] ^= key1[j%KEY_LENGTH];
    }
    return;
}
