
#!/usr/bin/env python3
import serial, sys, time
port = '/dev/ttyACM1'
ser = serial.Serial(port, 9600, timeout=None)
if not ser.is_open:
    ser.open()
    
def send_T():
    ser.write(b'T')  #  'T'
    print("Sent 'T' to trigger APP start")
    
def send_x():
    ser.write(b'x')  #  'x'
    print("Sent 'x' to trigger xor_compute")

def send_h():
    ser.write(b'h')  #  'h'
    print("Sent 'x' to trigger sha256_send")
    
def send_r():
    ser.write(b'r')  #  'r'
    print("Sent 'r' to trigger update")

def send_s():
    ser.write(b's')  #  's'
    print("Sent 's' to stop app")

def send_v():
    ser.write(b'v')  #  'v'
    print("Sent 'v' to trigger data_value_send")
    
send_T()    
#send_x()
#send_r()
#send_s()
ser.close()             # close port
