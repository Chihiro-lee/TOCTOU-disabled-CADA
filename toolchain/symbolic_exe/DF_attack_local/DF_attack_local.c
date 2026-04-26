#include <msp430.h>
#define LENGTH 10
char total = 0;
//char user_input[11] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x10,'\r'};
char user_input[6] = {0x01,0x02,0x03,0x04,0x05,'\r'};
void injectMedicinePort1(char* user_input){
  volatile char settings[5] = {1,1,1,1,1}; 
  volatile char local[8] = {2,2,2,2,2,2,2,2};
  int i = 0;
  while(user_input[i] != '\r'){
      settings[i] = user_input[i];
      total = 'a' ^ settings[i];
      i++;
  }
  for (int j = 0; j < 8; j++){
      total = local[j];
  }
}
int main(void)
{
  WDTCTL = WDTPW | WDTHOLD;
  P1DIR |= BIT0;              
  P1OUT &= 0xfe;
  P4DIR |= BIT7;
  injectMedicinePort1(user_input);
  if (total != 0){
      P4OUT |= BIT7;
  }
  else{
      P1OUT |= BIT0;
  }
  return 0;
}
