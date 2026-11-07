param([Parameter(Mandatory=$true)][string]$ScenesPath)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Speech
$scenes = Get-Content -LiteralPath $ScenesPath -Raw | ConvertFrom-Json
$speaker = New-Object System.Speech.Synthesis.SpeechSynthesizer
$speaker.Rate = 0
try {
    foreach ($scene in $scenes) {
        $speaker.SetOutputToWaveFile($scene.audio)
        $speaker.Speak($scene.narration)
        $speaker.SetOutputToNull()
    }
} finally {
    $speaker.Dispose()
}
