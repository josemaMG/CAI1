# ==========================================
# corrupt-all.ps1
# Corrompe TODOS los .bin
# ==========================================

$dir = "X:"

$files = Get-ChildItem $dir -Filter *.bin

if ($files.Count -eq 0) {
    Write-Host "No se encontraron .bin en $dir"
    exit
}

foreach ($file in $files) {

    $fs=[System.IO.File]::Open($file.FullName,'Open','ReadWrite')

    $pos=Get-Random -Minimum 0 -Maximum $fs.Length
    $value=Get-Random -Minimum 0 -Maximum 256

    $fs.Seek($pos,0)
    $fs.WriteByte($value)

    $fs.Close()

    Write-Host "Corrompido $($file.Name) en byte $pos"
}

Write-Host "Corrupcion masiva completada."
