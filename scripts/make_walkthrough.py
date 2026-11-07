"""Generate an explicitly AI-narrated technical walkthrough from an actual report.

Optional Windows authoring dependencies: pip install pillow imageio-ffmpeg
Not used by the application or its offline inference pipeline.
"""
import argparse
import json
from pathlib import Path
import subprocess
import wave

import imageio_ffmpeg
from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[1]
MEDIA = ROOT / "docs" / "media"
BG, INK, MUTED, ACCENT = "#111e19", "#f2f5e9", "#9baea0", "#c8e5a0"


def font(size, bold=False):
    return ImageFont.truetype("C:/Windows/Fonts/segoeuib.ttf" if bold else "C:/Windows/Fonts/segoeui.ttf", size)


def wrap(draw, text, width, size):
    lines, line = [], ""
    for word in text.split():
        attempt = (line + " " + word).strip()
        if draw.textlength(attempt, font=font(size)) > width and line:
            lines.append(line)
            line = word
        else:
            line = attempt
    return lines + [line]


def slide(number, title, subtitle, items, metric=None):
    im = Image.new("RGB", (1600, 900), BG)
    d = ImageDraw.Draw(im)
    d.rounded_rectangle((70, 56, 126, 112), 14, fill=ACCENT)
    d.text((81, 63), "c8", font=font(29,True), fill=BG)
    d.text((145,64), "cultive8.", font=font(32,True), fill=INK)
    d.text((1260,75), f"TECHNICAL WALKTHROUGH   {number:02d}", font=font(14), fill=MUTED)
    d.line((70,142,1530,142), fill="#34473a", width=1)
    d.text((76,195),title,font=font(57,True),fill=INK)
    y=278
    for line in wrap(d,subtitle,1430,27):
        d.text((80,y),line,font=font(27),fill=MUTED); y+=40
    y=385
    for label,body in items:
        d.rounded_rectangle((80,y,1520,y+98),10,fill="#203328")
        d.text((106,y+15),label,font=font(23,True),fill=ACCENT)
        for index,line in enumerate(wrap(d,body,1050,22)):
            d.text((410,y+18+index*30),line,font=font(22),fill=INK)
        y+=117
    if metric:
        d.text((82,765),metric,font=font(24,True),fill=ACCENT)
    d.line((70,830,1530,830),fill="#34473a",width=1)
    d.text((80,851),"AI-generated narration  /  Implementation explanation  /  Review before submission",font=font(16),fill=MUTED)
    d.text((1320,851),"LOCAL AI · CPU ONLY",font=font(15),fill=MUTED)
    path=MEDIA/f"scene-{number}.png"; im.save(path)
    return path


def main():
    parser=argparse.ArgumentParser();parser.add_argument("report");args=parser.parse_args()
    report=json.loads(Path(args.report).read_text(encoding="utf-8-sig"))
    if not report["complete"]:
        raise SystemExit("A completed actual report is required")
    MEDIA.mkdir(exist_ok=True)
    types=", ".join(f["type"] for f in report["findings"])
    scenes=[
      ("A local lens on server security.", "Upload a log. Follow the evidence. Investigate connected events.",
       [("OFFLINE", "Downloaded Qwen2.5 1.5B, quantized to Q4_K_M."),("LIGHTWEIGHT", "FastAPI, SQLite and a browser dashboard. No frontend build."),("PRIVATE", "Loopback inference. No cloud model calls. No log commands executed.")],
       "This is an AI-narrated implementation walkthrough for the Cultive8 assessment. The application accepts a server log and produces a consolidated security report using a downloaded local model. The backend uses Fast API and SQLite. The dashboard uses local HTML, CSS and JavaScript, so the main application works offline after setup."),
      ("The entire call fits in 2,048 tokens.", "The budget includes instructions, saved context, log text, and the reply.",
       [("1,648 INPUT", "Apply the model's chat template, then count its exact token IDs."),("384 OUTPUT", "Reserve the reply budget before adding log entries."),("16 SAFETY", "Send the exact counted array. Disable silent context shifting.")],
       "The most important constraint is the total token budget. One thousand six hundred and forty eight tokens are available for the full input, three hundred and eighty four for output, and sixteen for safety. The backend applies the model's own chat template and tokenizer, then submits exactly those counted token IDs. Whole entries stay together where possible. Oversized entries use tracked fragments without losing text."),
      ("Small chunks. Durable evidence.", "Each successful call and its next cursor commit in one transaction.",
       [("READ", "Stream uploads, retain physical line numbers and deduplicate exact entries."),("ANALYZE", "Process one model call at a time; carry relevant prior facts forward."),("RESUME", "Checkpoint calls in SQLite. Retry safely; preserve completed work.")],
       "Logs are streamed into a source index with original line numbers. Exact duplicate entries are counted once during correlation. The queue processes one local model call at a time. Each successful response and the next source cursor commit together. I verified pause, backend restart and resume against the supplied log. Invalid or incomplete model replies never advance the checkpoint."),
      ("Connect events across the file.", f"Actual supplied-log run: {report['total_lines']} lines, {report['calls']} saved model calls, {len(report['findings'])} final findings.",
       [("INDEX", "Group authentication by IP, application and account; compare event times."),("REVIEW", "Nominate candidates from evidence; ask the local model to adjudicate."),("EXPLAIN", "Show source lines, model citations, severity, reason and suggested action.")],
       f"The supplied log has {report['total_lines']} physical lines. The completed run used {report['calls']} saved model calls and produced {len(report['findings'])} findings. The index links failed logins with later successful authentication and session activity. Every final candidate receives a separate local model review. Rules alone cannot publish a finding. The report exposes the original evidence and contributing chunks."),
      ("Ground model claims in source data.", "A valid JSON response is not automatically a valid security finding.",
       [("ATTRIBUTION", "Reject invented line numbers and evidence belonging to a different entity."),("TRUSTED REPORT", "Render source-derived explanations and fixed remediation guidance."),("UNTRUSTED DATA", "Keep raw model prose in the audit. Never execute log instructions.")],
       "The small model sometimes misclassified normal requests and cited other IPs. The adversarial log also contaminated a proposed action with a suggestion to remove evidence. Nothing was executed. The final report now derives explanations from validated source facts and uses trusted remediation guidance. The model still adjudicates candidates, but its raw prose stays in the audit. Prompt wording alone is not a security boundary."),
      ("Designed for a small machine.", "Measured behavior, explicit tradeoffs, and reproducible setup.",
       [("RESOURCES", "Two inference threads, one slot, CPU only, large prompt cache disabled."),("VERIFICATION", "Regression tests plus a real-model run on the unchanged supplied log."),("LIMITS", "Small-model reasoning and arbitrary text formats need human review.")],
       "The runtime uses two CPU threads, one inference slot and no GPU layers. The large prompt cache is disabled. The dashboard reports process memory and call timings. The repository includes regression tests, setup documentation and an AI usage record. Findings still require human investigation. The Windows host is not a two virtual CPU benchmark, and the optional Docker resource-limit configuration has not been independently tested. Review the code and record your own explanation before submission.")
    ]
    audio=[]
    for n,(title,sub,items,narration) in enumerate(scenes,1):
        slide(n,title,sub,items)
        audio.append({"narration":narration,"audio":str(MEDIA/f"scene-{n}.wav")})
    scene_path=MEDIA/"narration.json";scene_path.write_text(json.dumps(audio,indent=2),encoding="utf-8")
    subprocess.run(["powershell.exe","-NoProfile","-File",str(ROOT/"scripts/narrate.ps1"),"-ScenesPath",str(scene_path)],check=True)
    ffmpeg=imageio_ffmpeg.get_ffmpeg_exe()
    concat=[];seconds=0
    for n in range(1,len(scenes)+1):
        with wave.open(str(MEDIA/f"scene-{n}.wav")) as wav:
            duration=wav.getnframes()/wav.getframerate()+.7
        seconds+=duration
        output=MEDIA/f"scene-{n}.mp4"
        subprocess.run([ffmpeg,"-y","-loglevel","error","-loop","1","-i",str(MEDIA/f"scene-{n}.png"),"-i",str(MEDIA/f"scene-{n}.wav"),"-t",str(duration),"-c:v","libx264","-tune","stillimage","-preset","fast","-crf","23","-threads","2","-r","12","-pix_fmt","yuv420p","-c:a","aac","-b:a","128k","-af","apad",str(output)],check=True)
        concat.append(f"file 'scene-{n}.mp4'")
    listing=MEDIA/"concat.txt";listing.write_text("\n".join(concat),encoding="utf-8")
    final=ROOT/"docs/Cultive8_Technical_Walkthrough.mp4"
    subprocess.run([ffmpeg,"-y","-loglevel","error","-f","concat","-safe","0","-i",str(listing),"-c","copy","-movflags","+faststart",str(final)],check=True)
    print(json.dumps({"video":str(final),"seconds":round(seconds,1),"bytes":final.stat().st_size}))


if __name__ == "__main__":
    main()
