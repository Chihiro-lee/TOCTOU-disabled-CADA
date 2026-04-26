#include <msp430.h>
char global_array[5] = {0,0,0,0,0};     
char total = 0;                 
char another_var = 100;         

//char user_input[11] = {0x01, 0x02, 0x03, 0x04, 0x05,  0x06, 0x07, 0x08, 0x09, 0x10, '\r'};
char user_input[6] = {0x01, 0x02, 0x03, 0x04, 0x05, '\r'};

void injectMedicinePort1(char* user_input){
  int i = 0;
  
  while(user_input[i] != '\r'){
      global_array[i] = user_input[i]; 
      i++;
  }
}

int main(void)
{
  WDTCTL = WDTPW | WDTHOLD;
  P1DIR |= BIT0;              
  P1OUT &= 0xfe;
  P4DIR |= BIT7;
  
  
  injectMedicinePort1(user_input);

  
  if (total < 6){
      P4OUT |= BIT7;  
  }
  else{
      P1OUT |= BIT0;
  }
  
  return 0;
}
