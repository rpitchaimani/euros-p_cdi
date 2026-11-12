"""uart_capture.py -- log the board UART (OpenSDA COM port) to a file and stdout.
  python uart_capture.py COM17 60 boot.log      # port, seconds, output file
"""
import sys
import time

import serial

port, secs, out = sys.argv[1], float(sys.argv[2]), sys.argv[3]
with serial.Serial(port, 57600, timeout=0.2) as s, open(out, "wb") as f:
    t_end = time.time() + secs
    while time.time() < t_end:
        b = s.read(512)
        if b:
            f.write(b)
            f.flush()
            # reset noise is not ASCII; never let the console encoding kill the capture
            sys.stdout.buffer.write(b.decode("ascii", "replace").encode("ascii", "replace"))
            sys.stdout.flush()
