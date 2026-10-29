#!/bin/bash
# usage: rec.sh scene  (runs on VM: ffmpeg + scene)
/tmp/push.sh
instabox ssh technoxi-ise-demo -- "cd /data/workspace/rec/v8; mkdir -p ../out; NODE_OPTIONS= node scenes.mjs prep; DISPLAY=:1 xdotool mousemove 20 640; 
ffmpeg -loglevel error -y -f x11grab -draw_mouse 0 -framerate 30 -video_size 1920x1080 -i :1.0 -c:v libx264 -preset veryfast -crf 17 -pix_fmt yuv420p ../out/$1.mp4 </dev/null & FF=\$!; sleep 1.5;
NODE_OPTIONS= node scenes.mjs $1 2>&1 | tail -15; sleep 1; kill -INT \$FF; wait \$FF 2>/dev/null; ls -la ../out/$1.mp4"
