import subprocess, sys
clips = ["s1","s2","s3","s4","s5"]
FADE = 0.4
def dur(f): return float(subprocess.check_output(["ffprobe","-v","error","-show_entries","format=duration","-of","csv=p=0",f]).decode())
LEAD = {"s1": 1.35, "s2": 1.0, "s3": 1.0, "s4": 1.0, "s5": 1.0}
for c in clips:
    subprocess.check_call(["ffmpeg","-loglevel","error","-y","-ss",str(LEAD[c]),"-i",f"/tmp/v8/{c}.mp4","-c:v","libx264","-preset","veryfast","-crf","16","-pix_fmt","yuv420p",f"/tmp/v8/{c}_t.mp4"])
ds = [dur(f"/tmp/v8/{c}_t.mp4") for c in clips]
inputs = []
for c in clips: inputs += ["-i", f"/tmp/v8/{c}_t.mp4"]
fc = []; last = "[0:v]"; off = 0.0
for i in range(1, len(clips)):
    off += ds[i-1] - FADE
    fc.append(f"{last}[{i}:v]xfade=transition=fade:duration={FADE}:offset={off:.3f}[v{i}]")
    last = f"[v{i}]"
cmd = ["ffmpeg","-loglevel","error","-y"] + inputs + ["-filter_complex", ";".join(fc), "-map", last, "-c:v","libx264","-preset","slow","-crf","18","-pix_fmt","yuv420p","-r","30","-movflags","+faststart","/tmp/v8/master3.mp4"]
subprocess.check_call(cmd)
print("total ~", sum(ds) - FADE*(len(clips)-1))
