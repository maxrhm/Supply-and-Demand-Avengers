param(
    [Parameter(Mandatory = $true)]
    [string]$run
)

$sourcePath = Join-Path $run "Presentation\*"
$zipPath = Join-Path $run "Presentation.zip"
$pptxPath = Join-Path $run "Presentation.pptx"

if (Test-Path $pptxPath) {
    Remove-Item $pptxPath -Force
}

Compress-Archive -Path $sourcePath -DestinationPath $zipPath -Force
Rename-Item -Path $zipPath -NewName "Presentation.pptx" -Force