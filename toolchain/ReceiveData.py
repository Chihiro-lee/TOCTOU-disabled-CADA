#!/usr/bin/env python3
import serial
import time
import sys
import re

PORT = '/dev/ttyACM1'
BAUDRATE = 9600
DATABASE_FILE = './database.txt'   

IDLE_TIMEOUT = 2.0
TERMINATOR = b'\n\r'


def reformat_database():

    try:
        with open(DATABASE_FILE, 'r', encoding='ascii', errors='ignore') as f:
            content = f.read()


        content_no_breaks = content.replace('\r', '').replace('\n', '')



        #formatted_content = re.sub(r'(0000 T)', r'\1\n', content_no_breaks)
        formatted_content = re.sub(r'([0-9A-Fa-f]{4} T)', r'\1\n', content_no_breaks)

        formatted_content = re.sub(r'\n+', r'\n', formatted_content)


        formatted_content = formatted_content.strip() + '\n'


        with open(DATABASE_FILE, 'w', encoding='ascii', errors='ignore') as f:
            f.write(formatted_content)

        print(f"Database reformatted: one record per line ending with 'xxxx T', no extra blank lines -> {DATABASE_FILE}")
    except Exception as e:
        print(f"Error reformatting database: {e}")


def main():
    try:
        ser = serial.Serial(PORT, BAUDRATE, timeout=1)
        print(f"Receiving on {ser.name}")
    except serial.SerialException as e:
        print(f"Cannot open port {PORT}: {e}")
        sys.exit(1)


    open(DATABASE_FILE, 'w').close()

    buffer = bytearray()
    last_receive_time = time.time()

    try:
        while True:
            if ser.in_waiting > 0:
                data = ser.read(ser.in_waiting)
                if data:
                    print("Received:", data)
                    buffer.extend(data)
                    last_receive_time = time.time()

                    term_pos = buffer.find(TERMINATOR)
                    if term_pos != -1:
                        valid_data = buffer[:term_pos + len(TERMINATOR)]


                        with open(DATABASE_FILE, 'a', encoding='ascii', errors='ignore') as file:
                            try:
                                file.write(valid_data.decode('ascii', errors='ignore'))
                            except Exception:
                                file.write(valid_data.decode('ascii', errors='replace'))
                            file.flush()

                        buffer = buffer[term_pos + len(TERMINATOR):]

                        print("\nPacket accepted and appended")


                        reformat_database()


                        return

            if time.time() - last_receive_time > IDLE_TIMEOUT:
                print("wait for data...", end='\r')
                sys.stdout.flush()
                time.sleep(0.2)
                last_receive_time = time.time()

            if ser.in_waiting == 0:
                time.sleep(0.01)

    except KeyboardInterrupt:
        print("\nUser interrupt, quitting...")
    except Exception as e:
        print(f"\nException: {e}")
    finally:
        ser.close()
        print("Serial port closed.")


if __name__ == "__main__":
    main()
