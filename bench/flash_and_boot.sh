#!/usr/bin/env bash
# flash_and_boot.sh -- program all three cores in ONE load, boot, capture the UART.
#   ./flash_and_boot.sh [COMPORT] [capture_seconds] [noflash]
#   e.g. ./flash_and_boot.sh COM17 60          ./flash_and_boot.sh COM17 60 noflash
# Close S32 Design Studio first (one debugger connection at a time).
#
# Two PEMicro facts this script handles:
#  * every GDB `load` erases the flash module, so the three ELFs are merged into
#    build/chainrecon_all.srec and loaded once;
#  * while the debugger is attached, a core that core 0 releases through MC_ME
#    stops in debug halt at its entry address.  The script waits until each
#    core sits at its entry (Z4b 0x011D0000 on port 7226, Z2 0x013A0000 on 7228)
#    and resumes it.  Without a debugger attached (power-up / reset button)
#    the cores run on their own.
set -e
COM=${1:-COM17}
SECS=${2:-60}
HERE=$(cd "$(dirname "$0")" && pwd)
PE="/c/NXP/S32DS_Power_v2.1/eclipse/plugins/com.pemicro.debug.gdbjtag.ppc_1.8.7.201906071634/win32/pegdbserver_power_console.exe"
BIN=/c/NXP/S32DS_Power_v2.1/S32DS/build_tools/powerpc-eabivle-4_9/bin
GDB=$BIN/powerpc-eabivle-gdb
LOG=$HERE/build/pegdb.log
cd "$HERE"

server() {   # $1 = extra flag; waits until ready, sets SPID
  "$PE" -startserver -device=MPC5748G -interface=OPENSDA -port=USB1 -serverport=7224 \
        -corenum=1 $1 > "$LOG" 2>&1 &
  SPID=$!
  for i in $(seq 1 40); do grep -q "All Servers Running" "$LOG" 2>/dev/null && return 0; sleep 1; done
  echo "GDB server did not start:"; tail -20 "$LOG"; exit 1
}
pc_of() {    # $1 port, $2 elf -> prints pc (hex) of that core
  timeout 30 "$GDB" -nx --batch -ex "set architecture powerpc:vle" -ex "target remote localhost:$1" \
     -ex "printf \"PC=%x\\n\", \$pc" -ex "detach" "$2" 2>/dev/null | grep -o "PC=[0-9a-f]*" | cut -d= -f2
}

if [ "$3" != "noflash" ]; then
  for c in 0 1 2; do
    $BIN/powerpc-eabivle-objcopy -O srec --srec-forceS3 --srec-len=32 -R ".*bss*" -R ".stack*" \
        build/chainrecon_c$c.elf build/chainrecon_c$c.srec
  done
  python python/merge_srec.py
  echo "== programming"
  server -singlesession
  "$GDB" -nx --batch -ex "set architecture powerpc:vle" -ex "target remote localhost:7224" \
         -ex "load build/chainrecon_all.srec" -ex "detach" 2>&1 | tail -1
  wait $SPID || true
  grep -E "Checksum|PE-ERROR" "$LOG" | grep -v "Can't read" || true
fi

echo "== boot (UART $COM, ${SECS}s)"
python python/uart_capture.py "$COM" "$SECS" build/boot.log > /dev/null &
CPID=$!
sleep 1
server ""
pc_of 7224 build/chainrecon_c0.elf > /dev/null          # detach = core 0 runs
for spec in "7226 build/chainrecon_c1.elf 11d0000" "7228 build/chainrecon_c2.elf 13a0000"; do
  set -- $spec
  for i in $(seq 1 45); do                                # wait until core 0 released it
    pc=$(pc_of $1 $2 || true)
    if [ "$pc" = "$3" ]; then echo "core on port $1 released at 0x$pc -> resumed"; break; fi
    sleep 1
  done
done
wait $CPID || true
kill $SPID 2>/dev/null || true
echo "== UART"
python -c "import sys;sys.stdout.write(open('build/boot.log','rb').read().decode('ascii','replace').encode('ascii','replace').decode())"
