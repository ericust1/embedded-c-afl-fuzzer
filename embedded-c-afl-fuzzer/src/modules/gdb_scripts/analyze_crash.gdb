set pagination off
set confirm off
file TARGET_BINARY
run < CRASH_FILE
bt full
info registers
x/16wx $rsp
info frame
quit
