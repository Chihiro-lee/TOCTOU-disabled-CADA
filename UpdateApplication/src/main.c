/*
  This sample application simply calls the receiveUpdate API to
  initiate a secure update.
*/
#include <RAhook.h>
int func(void)
{
  int a = 0;
  int b = 1;
  int c = 2;
  return a+b+c;
}
int main(void)
{
  int sum = func();
  callSendUpdate();
  return 0;
}
