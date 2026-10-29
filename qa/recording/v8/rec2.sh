#!/bin/bash
# usage: rec2.sh <pre|-> <scene>
/tmp/push.sh
PRE=$1; S=$2
instabox ssh technoxi-ise-demo -- "cd /data/workspace/rec/v8; mkdir -p ../out; DISPLAY=:1 xdotool mousemove 20 640;
[ '$PRE' != '-' ] && NODE_OPTIONS= node scenes2.mjs $PRE;
ffmpeg -loglevel error -y -f x11grab -draw_mouse 0 -framerate 30 -video_size 1920x1080 -i :1.0 -c:v libx264 -preset veryfast -crf 17 -pix_fmt yuv420p ../out/$S.mp4 </dev/null & FF=\$!; sleep 1.2;
SPEED=0.5 NODE_OPTIONS= node scenes2.mjs $S 2>&1 | tail -15; sleep 0.8; kill -INT \$FF; wait \$FF 2>/dev/null; ls -la ../out/$S.mp4"
