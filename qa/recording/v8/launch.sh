#!/bin/bash
export DISPLAY=:1
pkill -f /usr/lib/chromium/chromium; sleep 3
cd /data/home
nohup chromium --user-data-dir=/data/home/chrome-profiles/pc \
  --load-extension=/data/workspace/secure-access-policy-checker/extension \
  --remote-debugging-port=9222 --remote-allow-origins='*' --no-first-run --no-default-browser-check \
  --kiosk --window-size=1920,1080 --window-position=0,0 --force-device-scale-factor=1 \
  --disable-infobars --disable-session-crashed-bubble --hide-crash-restore-bubble --disable-dev-shm-usage \
  'https://idac.cat-dcloud.com/api/v2.0/request/stateless/0?owner=00uvka4kmcwwqpdxt5d7&recipeName=sa-instant-v1&datacenter=sng&recipePath=sec/&_open=ext' > /tmp/chrome_pc.log 2>&1 &
sleep 20
curl -s localhost:9222/json/list | grep -E '"(type|url)"' | cut -c1-140
